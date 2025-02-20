package main

import (
	"context"
	"log"
	"os"

	"github.com/akto-api-security/api-gateway-logging/logprocesser"
	"github.com/akto-api-security/api-gateway-logging/trafficUtil/kafkaUtil"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/config"
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

	assumeRoleOutput, err := stsSvc.AssumeRole(context.Background(), &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleArn),
		RoleSessionName: aws.String(sessionName),
	})
	if err != nil {
		log.Fatalf("unable to assume role: %v", err)
	}

	// Temporary credentials
	creds := credentials.NewStaticCredentialsProvider(
		*assumeRoleOutput.Credentials.AccessKeyId,
		*assumeRoleOutput.Credentials.SecretAccessKey,
		*assumeRoleOutput.Credentials.SessionToken,
	)

	// Create CloudWatch Logs client
	client := cloudwatchlogs.NewFromConfig(cfg, func(o *cloudwatchlogs.Options) {
		o.Credentials = creds
	})

	// Define the log group arn
	logGroupArn := os.Getenv("LOG_GROUP_ARN")
	if logGroupArn == "" {
		log.Fatalf("LOG_GROUP_ARN environment variable is required")
	}

	kafkaUtil.InitKafka()

	// Start monitoring the log group
	if err := logprocesser.MonitorLogGroup(context.TODO(), client, logGroupArn); err != nil {
		log.Fatalf("Error monitoring log group: %v", err)
	}
}
