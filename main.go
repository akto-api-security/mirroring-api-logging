package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/akto-api-security/api-gateway-logging/loggroupdiscovery"
	"github.com/akto-api-security/api-gateway-logging/logprocesser"
	"github.com/akto-api-security/api-gateway-logging/openapiprocessor"
	"github.com/akto-api-security/api-gateway-logging/trafficUtil/kafkaUtil"
	"github.com/akto-api-security/api-gateway-logging/trafficUtil/utils"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
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

	logGroupNames, err := getLogGroupNames(context.TODO(), cfg, client)
	if err != nil {
		utils.LogToCyborg("error", "Error Getting log groups: "+err.Error())
		log.Fatalf("Error Getting log groups: %v", err)
	}
	if len(logGroupNames) == 0 {
		utils.LogToCyborg("error", "No log group names: enable DISCOVER_EXECUTION_LOG_GROUPS")
		log.Fatalf("No log group names: enable DISCOVER_EXECUTION_LOG_GROUPS")
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

// getLogGroupNames returns the list of CloudWatch log group names to monitor.
// When discovery is enabled, fetches execution log groups for API Gateway REST APIs;
func getLogGroupNames(ctx context.Context, cfg aws.Config, logsClient *cloudwatchlogs.Client) ([]string, error) {

	discoverExecutionLogGroups := true
	utils.InitVar("DISCOVER_EXECUTION_LOG_GROUPS", &discoverExecutionLogGroups)

	var logGroupNames []string
	// fromEnv := parseLogGroupNamesFromEnv(os.Getenv("LOG_GROUP_NAME"))
	if discoverExecutionLogGroups {
		restClient := apigateway.NewFromConfig(cfg)
		discovered, err := loggroupdiscovery.GetExecutionLogGroupNames(ctx, restClient, logsClient)
		if err != nil {
			return nil, err
		}
		logGroupNames = discovered
		utils.LogToCyborg("info", "Discovered "+fmt.Sprint(len(discovered))+" execution log group(s). Log group names: "+strings.Join(discovered, ", "))
	}
	return logGroupNames, nil
}
