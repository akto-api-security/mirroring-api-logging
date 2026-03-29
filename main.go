package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/akto-api-security/api-gateway-logging/accountconfig"
	"github.com/akto-api-security/api-gateway-logging/loggroupdiscovery"
	"github.com/akto-api-security/api-gateway-logging/logprocesser"
	"github.com/akto-api-security/api-gateway-logging/openapiprocessor"
	"github.com/akto-api-security/api-gateway-logging/trafficUtil/kafkaUtil"
	"github.com/akto-api-security/api-gateway-logging/trafficUtil/utils"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func main() {
	fmt.Println("[STARTUP] Log Reader v2 with ACCOUNT_CONFIG debug logging - 2026-03-29")
	fmt.Println("[STARTUP] Starting log reader with cross-account mapping support")

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

	// Create CloudWatch Logs client and STS client
	client := cloudwatchlogs.NewFromConfig(cfg)
	stsClient := sts.NewFromConfig(cfg)

	// Check if cross-account mode is enabled
	crossAccountMode := false
	utils.InitVar("ENABLE_CROSS_ACCOUNT_MODE", &crossAccountMode)
	if crossAccountMode {
		utils.LogToCyborg("info", "Cross-account mode ENABLED - will discover log groups from customer AWS accounts")
	} else {
		utils.LogToCyborg("info", "Cross-account mode disabled - using single-account mode")
	}

	discoveredLogGroups, err := getLogGroupNames(context.TODO(), cfg, client, stsClient, crossAccountMode)
	if err != nil {
		utils.LogToCyborg("error", "Error Getting log groups: "+err.Error())
		log.Fatalf("Error Getting log groups: %v", err)
	}
	if len(discoveredLogGroups) == 0 {
		utils.LogToCyborg("error", "No log group names foud for monitoring")
		log.Fatalf("No log group names foud for monitoring")
	}

	utils.LogToCyborg("info", "Monitoring "+fmt.Sprint(len(discoveredLogGroups))+" log group(s)")

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

	// Initialize account mapping manager for AWS→Akto account ID mapping
	cyborgBaseURL := os.Getenv("CYBORG_BASE_URL")
	if cyborgBaseURL == "" {
		cyborgBaseURL = "https://ultron.akto.io"
	}
	accountMappingRefreshMinutes := 5
	utils.InitVar("ACCOUNT_MAPPING_REFRESH_MINUTES", &accountMappingRefreshMinutes)
	accountconfig.Initialize(cyborgBaseURL, databaseAbstractorToken, accountMappingRefreshMinutes)

	for _, discoveredLg := range discoveredLogGroups {
		go func(lg loggroupdiscovery.DiscoveredLogGroup) {
			utils.LogToCyborg("info", "Starting CloudWatch monitor for log group: "+lg.Name)
			if err := logprocesser.MonitorLogGroup(context.TODO(), client, lg.Name, lg.AwsAccountId); err != nil {
				utils.LogToCyborg("error", "Error monitoring log group "+lg.Name+": "+err.Error())
				log.Fatalf("Error monitoring log group %s: %v", lg.Name, err)
			}
		}(discoveredLg)
	}

	// Start OpenAPI spec discovery if enabled (does not block CloudWatch monitoring)
	if discoverOpenAPISpec {
		utils.LogToCyborg("info", "OpenAPI spec discovery enabled with "+fmt.Sprint(openapiDiscoveryIntervalMinutes)+" minute interval")

		go func() {
			log.Printf("OpenAPI discovery goroutine started")
			ticker := time.NewTicker(time.Duration(openapiDiscoveryIntervalMinutes) * time.Minute)
			defer ticker.Stop()

			for {
				if crossAccountMode {
					// Cross-account mode: discover OpenAPI specs from all customer AWS accounts
					mappings := accountconfig.GetAllMappings()
					if len(mappings) == 0 {
						utils.LogToCyborg("warn", "Cross-account mode enabled but no AWS account mappings found for OpenAPI discovery")
					} else {
						utils.LogToCyborg("info", fmt.Sprintf("Discovering OpenAPI specs from %d customer AWS accounts", len(mappings)))
						for awsAccountId := range mappings {
							// Create API Gateway clients for customer account using STS AssumeRole
							clientSet, err := openapiprocessor.CreateAPIGatewayClientsForAccount(context.TODO(), cfg, stsClient, awsAccountId)
							if err != nil {
								utils.LogToCyborg("warn", fmt.Sprintf("Failed to create API Gateway clients for account %s: %v", awsAccountId, err))
								continue
							}

							openapiprocessor.MonitorAPIs(
								context.TODO(),
								clientSet,
								awsAccountId,
								awsRegion,
								databaseAbstractorToken,
							)
						}
					}
				} else {
					// Single-account mode: discover OpenAPI specs from deployed account only
					clientSet, err := openapiprocessor.CreateAPIGatewayClients(cfg)
					if err != nil {
						utils.LogToCyborg("warn", "OpenAPI discovery disabled - failed to create API Gateway clients: "+err.Error())
						log.Printf("Set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY (and optionally AWS_SESSION_TOKEN) for OpenAPI spec discovery")
						return
					}

					openapiprocessor.MonitorAPIs(
						context.TODO(),
						clientSet,
						"default-account",
						awsRegion,
						databaseAbstractorToken,
					)
				}

				<-ticker.C
			}
		}()
	}

	utils.LogToCyborg("info", "All monitors started, main loop running")
	// Keep the application running
	select {}
}

// getLogGroupNames returns the list of discovered CloudWatch log groups to monitor.
// Fetches execution log groups for API Gateway REST APIs, supporting both single-account and cross-account modes.
func getLogGroupNames(
	ctx context.Context,
	cfg aws.Config,
	logsClient *cloudwatchlogs.Client,
	stsClient *sts.Client,
	crossAccountMode bool,
) ([]loggroupdiscovery.DiscoveredLogGroup, error) {
	restClient := apigateway.NewFromConfig(cfg)
	discovered, err := loggroupdiscovery.GetExecutionLogGroupNames(ctx, restClient, logsClient, stsClient, cfg, crossAccountMode)
	if err != nil {
		utils.LogToCyborg("error", "Error discovering execution log groups: "+err.Error())
		return nil, err
	}

	var logGroupNames []string
	for _, lg := range discovered {
		logGroupNames = append(logGroupNames, lg.Name)
	}
	utils.LogToCyborg("info", "Discovered "+fmt.Sprint(len(discovered))+" execution log group(s). Log group names: "+strings.Join(logGroupNames, ", "))
	return discovered, nil
}
