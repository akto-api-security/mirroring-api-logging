package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/akto-api-security/api-gateway-logging/logprocesser"
	"github.com/akto-api-security/api-gateway-logging/openapiprocessor"
	"github.com/akto-api-security/api-gateway-logging/trafficUtil/kafkaUtil"
	"github.com/akto-api-security/api-gateway-logging/trafficUtil/utils"
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
	roleArns := strings.Split(roleArn, ",")

	sessionName := os.Getenv("SESSION_NAME")
	if sessionName == "" {
		sessionName = "aktologprocesser"
	}

	// Create a map of CloudWatch Logs clients per role ARN
	clientsPerRole := make(map[string]*cloudwatchlogs.Client)

	for _, roleArn := range roleArns {
		createArnClient(roleArn, cfg, stsSvc, sessionName, clientsPerRole)
	}

	kafkaUtil.InitKafka()

	// Map of API Gateway clients per role ARN (for OpenAPI discovery)
	apiGatewayClientsPerRole := make(map[string]*openapiprocessor.ClientSet)

	monitored := make(map[string]bool)
	var mu sync.Mutex

	awsRoleArnsFromAkto := []string{}

	databaseAbstractorToken := os.Getenv("DATABASE_ABSTRACTOR_TOKEN")
	if databaseAbstractorToken != "" {
		setRoleArns(databaseAbstractorToken, &awsRoleArnsFromAkto, &mu)
		go func() {
			ticker := time.NewTicker(4 * time.Minute)
			defer ticker.Stop()
			for {
				setRoleArns(databaseAbstractorToken, &awsRoleArnsFromAkto, &mu)
				<-ticker.C
			}
		}()
	}
	// Get ticker interval from environment variable, default to 5 minutes
	tickerIntervalMinutes := 5
	if intervalStr := os.Getenv("TICKER_INTERVAL_MINUTES"); intervalStr != "" {
		if interval, err := strconv.Atoi(intervalStr); err == nil && interval > 0 {
			tickerIntervalMinutes = interval
		} else {
			log.Printf("Invalid TICKER_INTERVAL_MINUTES value '%s', using default of 5 minutes", intervalStr)
		}
	}
	log.Printf("Ticker interval set to %d minutes", tickerIntervalMinutes)

	// OpenAPI discovery feature flag (enabled by default)
	discoverOpenAPISpec := true
	utils.InitVar("DISCOVER_OPENAPI_SPEC", &discoverOpenAPISpec)

	// OpenAPI discovery polling interval (default: 15 minutes)
	openapiDiscoveryIntervalMinutes := 15
	utils.InitVar("OPENAPI_DISCOVERY_INTERVAL_MINUTES", &openapiDiscoveryIntervalMinutes)

	// OpenAPI discovery requires DATABASE_ABSTRACTOR_TOKEN for cyborg auth
	if discoverOpenAPISpec && databaseAbstractorToken == "" {
		log.Printf("WARNING: DATABASE_ABSTRACTOR_TOKEN not set - disabling OpenAPI discovery")
		discoverOpenAPISpec = false
	}

	go func() {
		ticker := time.NewTicker(time.Duration(tickerIntervalMinutes) * time.Minute)
		defer ticker.Stop()

		for {
			mu.Lock()
			roleArns := make([]string, len(awsRoleArnsFromAkto))
			copy(roleArns, awsRoleArnsFromAkto)
			mu.Unlock()

			log.Printf("Using AWS Role ARNs: %v\n", roleArns)

			// Fetch log groups from all configured roles
			var roleArnToLogMap = make(map[string][]string)
			for _, roleArn := range roleArns {

				_, exists := clientsPerRole[roleArn]
				if !exists {
					createArnClient(roleArn, cfg, stsSvc, sessionName, clientsPerRole)
				}

				log.Printf("Fetching log groups for role: %s", roleArn)
				logGroups, err := fetchAllLogGroupARNs(context.TODO(), clientsPerRole[roleArn])
				if err != nil {
					log.Printf("Failed to fetch log groups for role %s: %v", roleArn, err)
					continue
				}
				roleArnToLogMap[roleArn] = logGroups
			}

			mu.Lock()
			for roleArn, logGroups := range roleArnToLogMap {
				for _, arn := range logGroups {
					if !monitored[arn] {
						monitored[arn] = true
						client := clientsPerRole[roleArn]
						go func(logGroupArn string, clientToUse *cloudwatchlogs.Client) {
							utils.DebugLog("Starting log processor for new log group: %s using client for role %s", logGroupArn, roleArn)
							if err := logprocesser.MonitorLogGroup(context.TODO(), clientToUse, logGroupArn); err != nil {
								log.Printf("Error monitoring log group %s: %v", logGroupArn, err)
							}
						}(arn, client)
					}
				}
			}
			mu.Unlock()

			<-ticker.C
		}
	}()

	// Start OpenAPI spec discovery if enabled (DOES NOT MODIFY CLOUDWATCH LOGIC)
	if discoverOpenAPISpec {
		log.Printf("OpenAPI spec discovery enabled with %d minute interval", openapiDiscoveryIntervalMinutes)

		go func() {
			ticker := time.NewTicker(time.Duration(openapiDiscoveryIntervalMinutes) * time.Minute)
			defer ticker.Stop()

			for {
				mu.Lock()
				roleArns := make([]string, len(awsRoleArnsFromAkto))
				copy(roleArns, awsRoleArnsFromAkto)
				mu.Unlock()

				log.Printf("Discovering OpenAPI specs for %d roles", len(roleArns))

				for _, roleArn := range roleArns {
					// Create API Gateway clients if not exist
					_, exists := apiGatewayClientsPerRole[roleArn]
					if !exists {
						clientSet, err := openapiprocessor.CreateAPIGatewayClients(
							roleArn, cfg, stsSvc, sessionName,
						)
						if err != nil {
							log.Printf("Failed to create API Gateway clients for role %s: %v", roleArn, err)
							continue
						}
						apiGatewayClientsPerRole[roleArn] = clientSet
					}

					// Spawn goroutine per role for API discovery
					clientSet := apiGatewayClientsPerRole[roleArn]
					go func(rArn string, cs *openapiprocessor.ClientSet) {
						log.Printf("Starting OpenAPI discovery for role: %s", rArn)
						openapiprocessor.MonitorAPIs(
							context.TODO(),
							cs,
							rArn,
							awsRegion,
							databaseAbstractorToken,
						)
					}(roleArn, clientSet)
				}

				<-ticker.C
			}
		}()
	}

	select {}
}

func setRoleArns(databaseAbstractorToken string, awsRoleArnsFromAkto *[]string, mu *sync.Mutex) {
	awsAccountIds, err := fetchAwsAccountIds(databaseAbstractorToken)
	if err != nil {
		log.Printf("Error fetching AWS Role ARNs from Akto: %v", err)
	} else {
		log.Printf("Fetched AWS Role ARNs from Akto: %v", awsAccountIds)
		mu.Lock()
		*awsRoleArnsFromAkto = parseRoleArns(awsAccountIds)
		log.Printf("Updated AWS Role ARNs: %v\n", *awsRoleArnsFromAkto)
		mu.Unlock()
	}
}

func fetchAwsAccountIds(token string) (string, error) {
	url := "https://cyborg.akto.io/api/fetchAwsAccountIdsForApiGatewayLogging"
	postBody := bytes.NewBuffer([]byte("{}"))
	req, err := http.NewRequest("POST", url, postBody)
	if err != nil {
		return "", err
	}
	req.Header.Set("authorization", token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	var parsed struct {
		AwsAccountIds string `json:"awsAccountIds"`
	}
	err = json.Unmarshal(body, &parsed)
	if err != nil {
		return "", fmt.Errorf("failed to parse response: %v, body: %s", err, string(body))
	}

	return parsed.AwsAccountIds, nil
}

func fetchAllLogGroupARNs(ctx context.Context, client *cloudwatchlogs.Client) ([]string, error) {
	var logGroupARNs []string
	var nextToken *string

	var IncludeLinkedAccounts = true

	logPrefix := os.Getenv("LOG_GROUP_PREFIX")
	if logPrefix == "" {
		// ref: https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html#apigateway-cloudwatch-log-formats
		logPrefix = "API-Gateway-Execution-Logs"
	}

	log.Printf("Using log group prefix: %s\n", logPrefix)

	for {
		input := &cloudwatchlogs.DescribeLogGroupsInput{
			NextToken:             nextToken,
			IncludeLinkedAccounts: &IncludeLinkedAccounts,
			LogGroupNamePrefix:    &logPrefix,
		}

		resp, err := client.DescribeLogGroups(ctx, input)
		if err != nil {
			return nil, err
		}

		for _, lg := range resp.LogGroups {
			log.Printf("Found Log Group ARN: %v\n", aws.ToString(lg.Arn))
			if lg.Arn != nil {
				arn := strings.TrimSuffix(*lg.Arn, ":*")
				logGroupARNs = append(logGroupARNs, arn)
			} else if lg.LogGroupName != nil {
				log.Printf("LogGroupName without ARN: %s\n", *lg.LogGroupName)
			}
		}

		if resp.NextToken == nil {
			break
		}
		nextToken = resp.NextToken
	}

	return logGroupARNs, nil
}

func isRoleArn(s string) bool {
	return strings.HasPrefix(s, "arn:aws:iam::") && strings.Contains(s, ":role/")
}

func parseRoleArns(input string) []string {
	result := []string{}
	if input == "" {
		return result
	}
	parts := strings.Split(input, ",")
	for _, part := range parts {
		id := strings.TrimSpace(part)
		if id != "" && isRoleArn(id) {
			result = append(result, id)
		}
	}
	return result
}

func createArnClient(roleArn string, cfg aws.Config, stsSvc *sts.Client, sessionName string, clientsPerRole map[string]*cloudwatchlogs.Client) {
	roleArn = strings.TrimSpace(roleArn)
	if roleArn == "" {
		return
	}

	// Create role-specific configuration
	roleCfg := cfg.Copy()

	// Temporary credentials for this role
	creds := stscreds.NewAssumeRoleProvider(stsSvc, roleArn, func(o *stscreds.AssumeRoleOptions) {
		o.RoleSessionName = sessionName
	})

	roleCfg.Credentials = aws.NewCredentialsCache(creds)

	// Create CloudWatch Logs client for this role
	client := cloudwatchlogs.NewFromConfig(roleCfg)
	clientsPerRole[roleArn] = client

	log.Printf("Created CloudWatch Logs client for role: %s", roleArn)
}
