package main

import (
	"context"
	"log"
	"os"

	"github.com/akto-api-security/api-gateway-logging/logprocesser"
	"github.com/akto-api-security/api-gateway-logging/trafficUtil/kafkaUtil"

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

	// Assume the cross-account role in Account B
	stsClient := sts.NewFromConfig(cfg)
	roleArn := os.Getenv("AWS_ROLE_ARN")
	if roleArn == "" {
		log.Fatalf("AWS_ROLE_ARN environment variable is required")
	}
	creds := stscreds.NewAssumeRoleProvider(stsClient, roleArn)

	// Create CloudWatch Logs client using the assumed role credentials
	client := cloudwatchlogs.NewFromConfig(cfg, func(o *cloudwatchlogs.Options) {
		o.Credentials = creds
	})

	// Define the log group name
	logGroupName := os.Getenv("LOG_GROUP_NAME")
	if logGroupName == "" {
		log.Fatalf("LOG_GROUP_NAME environment variable is required")
	}

	kafkaUtil.InitKafka()

	// Start monitoring the log group
	if err := logprocesser.MonitorLogGroup(context.TODO(), client, logGroupName); err != nil {
		log.Fatalf("Error monitoring log group: %v", err)
	}
}
