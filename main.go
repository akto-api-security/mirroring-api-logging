package main

import (
	"context"
	"log"
	"os"

	"github.com/akto-api-security/api-gateway-logging/logprocesser"
	"github.com/akto-api-security/api-gateway-logging/trafficUtil/kafkaUtil"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
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

	// Create CloudWatch Logs client
	client := cloudwatchlogs.NewFromConfig(cfg)

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
