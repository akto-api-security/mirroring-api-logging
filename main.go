package main

import (
	"context"
	"fmt"
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
		utils.LogToCyborg("error", "AWS_REGION environment variable is required")
		log.Fatalf("AWS_REGION environment variable is required")
	}

	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(awsRegion))
	if err != nil {
		utils.LogToCyborg("error", "Unable to load AWS configuration: "+err.Error())
		log.Fatalf("Unable to load AWS configuration: %v", err)
	}
	utils.LogToCyborg("info", "AWS configuration loaded for region: "+awsRegion)

	// Create CloudWatch Logs client
	client := cloudwatchlogs.NewFromConfig(cfg)

	logGroupNamesRaw := os.Getenv("LOG_GROUP_NAME")
	if logGroupNamesRaw == "" {
		utils.LogToCyborg("error", "LOG_GROUP_NAME environment variable is required")
		log.Fatalf("LOG_GROUP_NAME environment variable is required")
	}

	utils.LogToCyborg("info", "Log group names: "+logGroupNamesRaw)

	var logGroupNames []string
	for _, name := range strings.Split(logGroupNamesRaw, ",") {
		name = strings.TrimSpace(name)
		if name != "" {
			logGroupNames = append(logGroupNames, name)
		}
	}
	if len(logGroupNames) == 0 {
		utils.LogToCyborg("error", "No valid log group names provided")
		log.Fatalf("No valid log group names provided")
	}
	utils.LogToCyborg("info", "Monitoring "+fmt.Sprint(len(logGroupNames))+" log group(s)")

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
		utils.LogToCyborg("warn", "DATABASE_ABSTRACTOR_TOKEN not set - disabling OpenAPI discovery")
		discoverOpenAPISpec = false
	}

	// Configurable lookback window from accountId (parsed from JWT in SetLookbackWindow)
	logprocesser.SetLookbackWindow(databaseAbstractorToken)

	for _, lgName := range logGroupNames {
		go func(name string) {
			utils.LogToCyborg("info", "Starting CloudWatch monitor for log group: "+name)
			if err := logprocesser.MonitorLogGroup(context.TODO(), client, name); err != nil {
				utils.LogToCyborg("error", "Error monitoring log group "+name+": "+err.Error())
				log.Fatalf("Error monitoring log group %s: %v", name, err)
			}
		}(lgName)
	}

	// Start OpenAPI spec discovery if enabled (does not block CloudWatch monitoring)
	if discoverOpenAPISpec {
		utils.LogToCyborg("info", "OpenAPI spec discovery enabled with "+fmt.Sprint(openapiDiscoveryIntervalMinutes)+" minute interval")

		go func() {
			log.Printf("OpenAPI discovery goroutine started")
			ticker := time.NewTicker(time.Duration(openapiDiscoveryIntervalMinutes) * time.Minute)
			defer ticker.Stop()

			// Create API Gateway clients for default AWS account (requires AWS credentials)
			clientSet, err := openapiprocessor.CreateAPIGatewayClients(cfg)
			if err != nil {
				utils.LogToCyborg("warn", "OpenAPI discovery disabled - failed to create API Gateway clients: "+err.Error())
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

	utils.LogToCyborg("info", "All monitors started, main loop running")
	// Keep the application running
	select {}
}
