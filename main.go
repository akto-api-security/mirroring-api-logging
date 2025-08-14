package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/akto-api-security/api-gateway-logging/logprocesser"
	"github.com/akto-api-security/api-gateway-logging/trafficUtil/kafkaUtil"
	"github.com/akto-api-security/api-gateway-logging/trafficUtil/utils"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func main() {
	// Load AWS configuration
	awsRegion := os.Getenv("AWS_REGION")
	if awsRegion == "" {
		log.Fatalf("AWS_REGION environment variable is required")
	}

	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(awsRegion)) // Replace with your AWS region
	if err != nil {
		log.Fatalf("Unable to load AWS configuration: %v", err)
	}

	stsSvc := sts.NewFromConfig(cfg)

	roleArn := os.Getenv("CROSS_ACCOUNT_ROLE_ARN")
	if roleArn == "" {
		log.Fatalf("CROSS_ACCOUNT_ROLE_ARN environment variable is required")
	}
	sessionName := os.Getenv("SESSION_NAME")
	if sessionName == "" {
		sessionName = "aktologprocesser"
	}

	if err != nil {
		log.Fatalf("unable to assume role: %v", err)
	}

	// Temporary credentials
	creds := stscreds.NewAssumeRoleProvider(stsSvc, roleArn, func(o *stscreds.AssumeRoleOptions) {
		o.RoleSessionName = sessionName
	})

	cfg.Credentials = aws.NewCredentialsCache(creds)

	// Create CloudWatch Logs client
	client := cloudwatchlogs.NewFromConfig(cfg)

	// Define the log group arn
	logGroupArn := os.Getenv("LOG_GROUP_AWS_ACCOUNT_ID")
	if logGroupArn == "" {
		log.Fatalf("LOG_GROUP_AWS_ACCOUNT_ID environment variable is required")
	}

	kafkaUtil.InitKafka()

	monitored := make(map[string]bool)
	var mu sync.Mutex

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			logGroups, err := fetchAllLogGroupARNs(context.TODO(), client, awsRegion)
			if err != nil {
				log.Printf("Failed to fetch log groups: %v", err)
				continue
			}

			mu.Lock()
			for _, arn := range logGroups {
				if !monitored[arn] {
					monitored[arn] = true
					go func(logGroupArn string) {
						utils.DebugLog("Starting log processor for new log group: %s", logGroupArn)
						if err := logprocesser.MonitorLogGroup(context.TODO(), client, logGroupArn); err != nil {
							log.Printf("Error monitoring log group %s: %v", logGroupArn, err)
						}
					}(arn)
				}
			}
			mu.Unlock()

			<-ticker.C
		}
	}()

	select {}
}


func fetchAllLogGroupARNs(ctx context.Context, client *cloudwatchlogs.Client, region string) ([]string, error) {
	var logGroupARNs []string
	var nextToken *string

	for {
		resp, err := client.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, err
		}

		for _, lg := range resp.LogGroups {
			if lg.Arn != nil {
				arn := strings.TrimSuffix(*lg.Arn, ":*")
				logGroupARNs = append(logGroupARNs, arn)
			} else if lg.LogGroupName != nil {
				// Fallback: build ARN manually
				logGroupARNs = append(logGroupARNs, fmt.Sprintf("arn:aws:logs:%s:%s:log-group:%s",
					region, os.Getenv("LOG_GROUP_AWS_ACCOUNT_ID"), *lg.LogGroupName))
			}
		}

		if resp.NextToken == nil {
			break
		}
		nextToken = resp.NextToken
	}

	return logGroupARNs, nil
}
