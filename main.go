package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/akto-api-security/api-gateway-logging/logprocesser"
	"github.com/akto-api-security/api-gateway-logging/openapiprocessor"
	"github.com/akto-api-security/api-gateway-logging/trafficUtil/kafkaUtil"
	"github.com/akto-api-security/api-gateway-logging/trafficUtil/utils"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
)

func main() {
	// Load AWS configuration
	awsRegion := os.Getenv("AWS_REGION")
	if awsRegion == "" {
		log.Fatalf("AWS_REGION environment variable is required")
	}

	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(awsRegion))
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

	// Initialize Kafka in background (non-blocking)
	// This allows OpenAPI discovery to start immediately even if Kafka is unavailable
	go kafkaUtil.InitKafka()

	// Get OpenAPI discovery configuration
	discoverOpenAPISpec := true
	utils.InitVar("DISCOVER_OPENAPI_SPEC", &discoverOpenAPISpec)

	openapiDiscoveryIntervalMinutes := 15
	utils.InitVar("OPENAPI_DISCOVERY_INTERVAL_MINUTES", &openapiDiscoveryIntervalMinutes)

	databaseAbstractorToken := os.Getenv("DATABASE_ABSTRACTOR_TOKEN")

	// OpenAPI discovery requires DATABASE_ABSTRACTOR_TOKEN for cyborg auth
	if discoverOpenAPISpec && databaseAbstractorToken == "" {
		log.Printf("WARNING: DATABASE_ABSTRACTOR_TOKEN not set - disabling OpenAPI discovery")
		discoverOpenAPISpec = false
	}

	// Start CloudWatch log monitoring in background
	go func() {
		if err := logprocesser.MonitorLogGroup(context.TODO(), client, logGroupName); err != nil {
			log.Fatalf("Error monitoring log group: %v", err)
		}
	}()

	// Start OpenAPI spec discovery if enabled (does not block CloudWatch monitoring)
	if discoverOpenAPISpec {
		log.Printf("OpenAPI spec discovery enabled with %d minute interval", openapiDiscoveryIntervalMinutes)

		go func() {
			ticker := time.NewTicker(time.Duration(openapiDiscoveryIntervalMinutes) * time.Minute)
			defer ticker.Stop()

			// Create API Gateway clients for default AWS account
			clientSet, err := openapiprocessor.CreateAPIGatewayClients(cfg)
			if err != nil {
				log.Fatalf("Failed to create API Gateway clients: %v", err)
			}

			for {
				// Use empty string for roleArn in single-account mode (used for logging only)
				openapiprocessor.MonitorAPIs(
					context.TODO(),
					clientSet,
					"default-account",
					awsRegion,
					databaseAbstractorToken,
				)

				<-ticker.C
			}
		}()
	}

	// Keep the application running
	select {}
}
