package main

import (
	"context"
	"log"
	"os"

	"github.com/akto-api-security/api-gateway-logging/logprocesser"
	"github.com/akto-api-security/api-gateway-logging/trafficUtil/kafkaUtil"

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

	log.Printf("Starting log processer for log group: %s \n", logGroupArn)

	// Start monitoring the log group
	if err := logprocesser.MonitorLogGroup(context.TODO(), client, logGroupArn); err != nil {
		log.Fatalf("Error monitoring log group: %v", err)
	}
}
