package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

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
	logGroupArn := os.Getenv("LOG_GROUP_ARN")
	if logGroupArn == "" {
		log.Fatalf("LOG_GROUP_ARN environment variable is required")
	}

	kafkaUtil.InitKafka()

	logGroupArns := strings.Split(logGroupArn, ",")

	for _, logGroupArnTemp := range logGroupArns {
		// Start monitoring the log group
		logGroupArnTemp = strings.Trim(logGroupArnTemp, " ")
		go func() {
			utils.DebugLog("Starting log processor for log group: %s", logGroupArnTemp)
			if err := logprocesser.MonitorLogGroup(context.TODO(), client, logGroupArnTemp); err != nil {
				log.Fatalf("Error monitoring log group: %v", err)
			}
		}()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)
	<-sig
	log.Println("Signaled to terminate")

}
