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
	os.Stdout.Sync()

	// Load AWS configuration
	fmt.Println("[STARTUP] Reading AWS_REGION environment variable")
	awsRegion := os.Getenv("AWS_REGION")
	if awsRegion == "" {
		fmt.Println("[STARTUP] ERROR: AWS_REGION not set")
		os.Stdout.Sync()
		utils.LogToCyborg("error", "AWS_REGION environment variable is required")
		log.Fatalf("AWS_REGION environment variable is required")
	}
	fmt.Printf("[STARTUP] AWS_REGION=%s\n", awsRegion)
	os.Stdout.Sync()

	fmt.Println("[STARTUP] Loading AWS configuration")
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(awsRegion))
	if err != nil {
		fmt.Printf("[STARTUP] ERROR loading AWS config: %v\n", err)
		os.Stdout.Sync()
		utils.LogToCyborg("error", "Unable to load AWS configuration: "+err.Error())
		log.Fatalf("Unable to load AWS configuration: %v", err)
	}
	fmt.Println("[STARTUP] AWS configuration loaded successfully")
	os.Stdout.Sync()
	utils.LogToCyborg("info", "AWS configuration loaded for region: "+awsRegion)

	// Create CloudWatch Logs client and STS client
	fmt.Println("[STARTUP] Creating CloudWatch Logs and STS clients")
	client := cloudwatchlogs.NewFromConfig(cfg)
	stsClient := sts.NewFromConfig(cfg)
	fmt.Println("[STARTUP] Clients created successfully")
	os.Stdout.Sync()

	// Check if cross-account mode is enabled
	fmt.Println("[STARTUP] Checking ENABLE_CROSS_ACCOUNT_MODE environment variable")
	crossAccountMode := false
	utils.InitVar("ENABLE_CROSS_ACCOUNT_MODE", &crossAccountMode)
	fmt.Printf("[STARTUP] ENABLE_CROSS_ACCOUNT_MODE=%v\n", crossAccountMode)
	os.Stdout.Sync()
	if crossAccountMode {
		fmt.Println("[STARTUP] Cross-account mode is ENABLED")
		os.Stdout.Sync()
		utils.LogToCyborg("info", "Cross-account mode ENABLED - will discover log groups from customer AWS accounts")
	} else {
		fmt.Println("[STARTUP] Cross-account mode is DISABLED")
		os.Stdout.Sync()
		utils.LogToCyborg("info", "Cross-account mode disabled - using single-account mode")
	}

	fmt.Println("[STARTUP] Calling getLogGroupNames()")
	os.Stdout.Sync()
	discoveredLogGroups, err := getLogGroupNames(context.TODO(), cfg, client, stsClient, crossAccountMode)
	if err != nil {
		fmt.Printf("[STARTUP] ERROR in getLogGroupNames: %v\n", err)
		os.Stdout.Sync()
		utils.LogToCyborg("error", "Error Getting log groups: "+err.Error())
		log.Fatalf("Error Getting log groups: %v", err)
	}
	fmt.Printf("[STARTUP] getLogGroupNames returned %d log groups\n", len(discoveredLogGroups))
	os.Stdout.Sync()
	if len(discoveredLogGroups) == 0 {
		fmt.Println("[STARTUP] ERROR: No log groups discovered")
		os.Stdout.Sync()
		utils.LogToCyborg("error", "No log group names foud for monitoring")
		log.Fatalf("No log group names foud for monitoring")
	}

	fmt.Printf("[STARTUP] Will monitor %d log group(s)\n", len(discoveredLogGroups))
	for i, lg := range discoveredLogGroups {
		fmt.Printf("[STARTUP]   [%d] %s (AWS Account: %s)\n", i+1, lg.Name, lg.AwsAccountId)
	}
	os.Stdout.Sync()
	utils.LogToCyborg("info", "Monitoring "+fmt.Sprint(len(discoveredLogGroups))+" log group(s)")

	// Initialize Kafka in background (non-blocking)
	// This allows OpenAPI discovery to start immediately even if Kafka is unavailable
	fmt.Println("[STARTUP] Starting Kafka initialization in background")
	os.Stdout.Sync()
	go kafkaUtil.InitKafka()

	// Get OpenAPI discovery configuration
	fmt.Println("[STARTUP] Reading OpenAPI discovery configuration")
	discoverOpenAPISpec := true
	utils.InitVar("DISCOVER_OPENAPI_SPEC", &discoverOpenAPISpec)

	openapiDiscoveryIntervalMinutes := 15
	utils.InitVar("OPENAPI_DISCOVERY_INTERVAL_MINUTES", &openapiDiscoveryIntervalMinutes)
	fmt.Printf("[STARTUP] DISCOVER_OPENAPI_SPEC=%v, interval=%d minutes\n", discoverOpenAPISpec, openapiDiscoveryIntervalMinutes)
	os.Stdout.Sync()

	fmt.Println("[STARTUP] Reading DATABASE_ABSTRACTOR_TOKEN")
	databaseAbstractorToken := os.Getenv("DATABASE_ABSTRACTOR_TOKEN")
	if databaseAbstractorToken == "" {
		fmt.Println("[STARTUP] DATABASE_ABSTRACTOR_TOKEN is empty")
	} else {
		fmt.Println("[STARTUP] DATABASE_ABSTRACTOR_TOKEN is set")
	}
	os.Stdout.Sync()

	// OpenAPI discovery requires DATABASE_ABSTRACTOR_TOKEN for cyborg auth
	if discoverOpenAPISpec && databaseAbstractorToken == "" {
		fmt.Println("[STARTUP] Disabling OpenAPI discovery (no token)")
		os.Stdout.Sync()
		utils.LogToCyborg("warn", "DATABASE_ABSTRACTOR_TOKEN not set - disabling OpenAPI discovery")
		discoverOpenAPISpec = false
	}

	// Initialize account mapping manager for AWS→Akto account ID mapping
	fmt.Println("[STARTUP] Reading CYBORG_BASE_URL")
	cyborgBaseURL := os.Getenv("CYBORG_BASE_URL")
	if cyborgBaseURL == "" {
		fmt.Println("[STARTUP] CYBORG_BASE_URL not set, using default: https://ultron.akto.io")
		cyborgBaseURL = "https://ultron.akto.io"
	} else {
		fmt.Printf("[STARTUP] CYBORG_BASE_URL=%s\n", cyborgBaseURL)
	}
	os.Stdout.Sync()

	accountMappingRefreshMinutes := 5
	utils.InitVar("ACCOUNT_MAPPING_REFRESH_MINUTES", &accountMappingRefreshMinutes)
	fmt.Printf("[STARTUP] About to call accountconfig.Initialize(url=%s, token=%s, refreshInterval=%d minutes)\n",
		cyborgBaseURL,
		map[bool]string{true: "SET", false: "EMPTY"}[databaseAbstractorToken != ""],
		accountMappingRefreshMinutes)
	os.Stdout.Sync()
	accountconfig.Initialize(cyborgBaseURL, databaseAbstractorToken, accountMappingRefreshMinutes)
	fmt.Println("[STARTUP] accountconfig.Initialize() completed")
	os.Stdout.Sync()

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
