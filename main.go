package main

import (
	"context"
	"log"
	"os"
	"strings"
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
	log.Printf("AWS configuration loaded for region: %s", awsRegion)

	// Create CloudWatch Logs client
	client := cloudwatchlogs.NewFromConfig(cfg)

	logGroupNamesRaw := os.Getenv("LOG_GROUP_NAME")
	if logGroupNamesRaw == "" {
		log.Fatalf("LOG_GROUP_NAME environment variable is required")
	}

	var logGroupNames []string
	for _, name := range strings.Split(logGroupNamesRaw, ",") {
		name = strings.TrimSpace(name)
		if name != "" {
			logGroupNames = append(logGroupNames, name)
		}
	}
	if len(logGroupNames) == 0 {
		log.Fatalf("No valid log group names provided")
	}
	log.Printf("Monitoring %d log group(s): %v", len(logGroupNames), logGroupNames)

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

	for _, lgName := range logGroupNames {
		go func(name string) {
			log.Printf("Starting CloudWatch monitor for log group: %s", name)
			if err := logprocesser.MonitorLogGroup(context.TODO(), client, name); err != nil {
				log.Fatalf("Error monitoring log group %s: %v", name, err)
			}
		}(lgName)
	}

	// Start OpenAPI spec discovery if enabled (does not block CloudWatch monitoring)
	if discoverOpenAPISpec {
		log.Printf("OpenAPI spec discovery enabled with %d minute interval", openapiDiscoveryIntervalMinutes)

		go func() {
			log.Printf("OpenAPI discovery goroutine started")
			ticker := time.NewTicker(time.Duration(openapiDiscoveryIntervalMinutes) * time.Minute)
			defer ticker.Stop()

			// Create API Gateway clients for default AWS account (requires AWS credentials)
			clientSet, err := openapiprocessor.CreateAPIGatewayClients(cfg)
			if err != nil {
				log.Printf("WARNING: OpenAPI discovery disabled - failed to create API Gateway clients: %v", err)
				log.Printf("Set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY (and optionally AWS_SESSION_TOKEN) for OpenAPI spec discovery")
				return
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

	log.Printf("All monitors started, main loop running")
	// Keep the application running
	select {}
}
