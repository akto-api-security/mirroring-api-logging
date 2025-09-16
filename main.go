package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"

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

	kafkaUtil.InitKafka()

	monitored := make(map[string]bool)
	var mu sync.Mutex

	awsAccountIdsFromAkto := []string{}

	logGroupAccountId := os.Getenv("LOG_GROUP_AWS_ACCOUNT_ID")
	awsAccountIdsFromAkto = parseNumericAccountIds(logGroupAccountId)

	databaseAbstractorToken := os.Getenv("DATABASE_ABSTRACTOR_TOKEN")
	if databaseAbstractorToken != "" {
		setAccountIds(databaseAbstractorToken, &awsAccountIdsFromAkto, &mu)
		go func() {
			ticker := time.NewTicker(4 * time.Minute)
			defer ticker.Stop()
			for {
				setAccountIds(databaseAbstractorToken, &awsAccountIdsFromAkto, &mu)
				<-ticker.C
			}
		}()
	}

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			mu.Lock()
			accountIds := make([]string, len(awsAccountIdsFromAkto))
			copy(accountIds, awsAccountIdsFromAkto)
			mu.Unlock()

			log.Printf("Using AWS Account IDs: %v\n", accountIds)
			logGroups, err := fetchAllLogGroupARNs(context.TODO(), client, accountIds)
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

func setAccountIds(databaseAbstractorToken string, awsAccountIdsFromAkto *[]string, mu *sync.Mutex) {
	awsAccountIds, err := fetchAwsAccountIds(databaseAbstractorToken)
	if err != nil {
		log.Printf("Error fetching AWS Account IDs from Akto: %v", err)
	} else {
		log.Printf("Fetched AWS Account IDs from Akto: %v", awsAccountIds)
		mu.Lock()
		*awsAccountIdsFromAkto = parseNumericAccountIds(awsAccountIds)
		log.Printf("Updated AWS Account IDs: %v\n", *awsAccountIdsFromAkto)
		mu.Unlock()
	}
}

func fetchAwsAccountIds(token string) (string, error) {
	url := "https://cyborg.akto.io/api/fetchAwsAccountIdsForApiGatewayLogging"
	postBody := bytes.NewBuffer([]byte("{}"))
	req, err := http.NewRequest("POST", url, postBody)
	if err != nil {
		return "", err
	}
	req.Header.Set("authorization", token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	var parsed struct {
		AwsAccountIds string `json:"awsAccountIds"`
	}
	err = json.Unmarshal(body, &parsed)
	if err != nil {
		return "", fmt.Errorf("failed to parse response: %v, body: %s", err, string(body))
	}

	return parsed.AwsAccountIds, nil
}

func fetchAllLogGroupARNs(ctx context.Context, client *cloudwatchlogs.Client, accountIds []string) ([]string, error) {
	var logGroupARNs []string
	var nextToken *string

	var IncludeLinkedAccounts = true

	logPrefix := os.Getenv("LOG_GROUP_PREFIX")
	if logPrefix == "" {
		// ref: https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html#apigateway-cloudwatch-log-formats
		logPrefix = "API-Gateway-Execution-Logs"
	}

	log.Printf("Using log group prefix: %s\n", logPrefix)

	for {
		input := &cloudwatchlogs.DescribeLogGroupsInput{
			NextToken:             nextToken,
			IncludeLinkedAccounts: &IncludeLinkedAccounts,
			LogGroupNamePrefix:    &logPrefix,
		}

		resp, err := client.DescribeLogGroups(ctx, input)
		if err != nil {
			return nil, err
		}

		log.Printf("Filtering log groups for account IDs: %v\n", accountIds)

		for _, lg := range resp.LogGroups {
			log.Printf("Found Log Group ARN: %v\n", aws.ToString(lg.Arn))
			if lg.Arn != nil {
				for _, accountId := range accountIds {
					if strings.Contains(*lg.Arn, accountId) {
						arn := strings.TrimSuffix(*lg.Arn, ":*")
						logGroupARNs = append(logGroupARNs, arn)
					}
				}
			} else if lg.LogGroupName != nil {
				log.Printf("LogGroupName without ARN: %s\n", *lg.LogGroupName)
			}
		}

		if resp.NextToken == nil {
			break
		}
		nextToken = resp.NextToken
	}

	return logGroupARNs, nil
}

func isNumeric(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func parseNumericAccountIds(input string) []string {
	result := []string{}
	if input == "" {
		return result
	}
	parts := strings.Split(input, ",")
	for _, part := range parts {
		id := strings.TrimSpace(part)
		if id != "" && isNumeric(id) {
			result = append(result, id)
		}
	}
	return result
}
