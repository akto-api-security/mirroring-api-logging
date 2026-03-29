package loggroupdiscovery

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/akto-api-security/api-gateway-logging/accountconfig"
	"github.com/akto-api-security/api-gateway-logging/trafficUtil/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const ApiGatewayExecutionLogGroupPrefix = "API-Gateway-Execution-Logs_"

// GetExecutionLogGroupNames returns CloudWatch log group names that are API Gateway
// execution log groups for REST APIs present in the account. It lists REST API IDs from
// API Gateway, lists log groups with prefix API-Gateway-Execution-Logs_, and keeps only
// those whose name contains a listed API ID.
//
// When crossAccountMode is true, discovers log groups from all customer AWS accounts using STS AssumeRole.
// When false, discovers from the deployed account only.
func GetExecutionLogGroupNames(
	ctx context.Context,
	restClient *apigateway.Client,
	logsClient *cloudwatchlogs.Client,
	stsClient *sts.Client,
	cfg aws.Config,
	crossAccountMode bool,
) ([]DiscoveredLogGroup, error) {
	fmt.Println("[LOG_DISCOVERY] GetExecutionLogGroupNames called")
	fmt.Printf("[LOG_DISCOVERY] crossAccountMode=%v\n", crossAccountMode)
	os.Stdout.Sync()

	if crossAccountMode {
		fmt.Println("[LOG_DISCOVERY] Calling discoverLogGroupsCrossAccount()")
		os.Stdout.Sync()
		return discoverLogGroupsCrossAccount(ctx, logsClient, stsClient, cfg)
	}
	fmt.Println("[LOG_DISCOVERY] Calling discoverLogGroupsSingleAccount()")
	os.Stdout.Sync()
	return discoverLogGroupsSingleAccount(ctx, restClient, logsClient)
}

// discoverLogGroupsSingleAccount discovers log groups from the deployed account (original behavior)
func discoverLogGroupsSingleAccount(
	ctx context.Context,
	restClient *apigateway.Client,
	logsClient *cloudwatchlogs.Client,
) ([]DiscoveredLogGroup, error) {
	apiIDs, err := listRestAPIIds(ctx, restClient)
	if err != nil {
		return nil, err
	}
	if len(apiIDs) == 0 {
		return nil, nil
	}

	var discovered []DiscoveredLogGroup
	paginator := cloudwatchlogs.NewDescribeLogGroupsPaginator(logsClient, &cloudwatchlogs.DescribeLogGroupsInput{
		LogGroupNamePrefix: strPtr(ApiGatewayExecutionLogGroupPrefix),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			utils.LogToCyborg("error", "Error describing log groups: "+err.Error())
			return nil, err
		}
		for _, lg := range page.LogGroups {
			if lg.LogGroupName == nil {
				continue
			}
			name := strings.TrimSpace(*lg.LogGroupName)
			if !strings.HasPrefix(name, ApiGatewayExecutionLogGroupPrefix) {
				continue
			}
			for _, apiID := range apiIDs {
				if strings.Contains(name, apiID) {
					discovered = append(discovered, DiscoveredLogGroup{
						Name:        name,
						AwsAccountId: "", // Single-account mode doesn't track account ID
					})
					utils.LogToCyborg("info", "Discovered API Gateway log group: "+name)
					break
				}
			}
		}
	}
	return discovered, nil
}

// discoverLogGroupsCrossAccount discovers log groups from all customer AWS accounts
func discoverLogGroupsCrossAccount(
	ctx context.Context,
	logsClient *cloudwatchlogs.Client,
	stsClient *sts.Client,
	cfg aws.Config,
) ([]DiscoveredLogGroup, error) {
	fmt.Println("[LOG_DISCOVERY_CROSS_ACCOUNT] Starting cross-account discovery")
	os.Stdout.Sync()

	// Get all AWS account IDs from account mappings
	fmt.Println("[LOG_DISCOVERY_CROSS_ACCOUNT] Calling accountconfig.GetAllMappings()")
	os.Stdout.Sync()
	mappings := accountconfig.GetAllMappings()
	fmt.Printf("[LOG_DISCOVERY_CROSS_ACCOUNT] GetAllMappings returned %d mappings\n", len(mappings))
	os.Stdout.Sync()

	if len(mappings) == 0 {
		fmt.Println("[LOG_DISCOVERY_CROSS_ACCOUNT] ERROR: No AWS account mappings found!")
		os.Stdout.Sync()
		utils.LogToCyborg("warn", "Cross-account mode enabled but no AWS account mappings found")
		return nil, nil
	}

	var allDiscovered []DiscoveredLogGroup
	var awsAccountIds []string
	for awsAccountId := range mappings {
		awsAccountIds = append(awsAccountIds, awsAccountId)
	}

	fmt.Printf("[LOG_DISCOVERY_CROSS_ACCOUNT] AWS Account IDs: %v\n", awsAccountIds)
	os.Stdout.Sync()
	utils.LogToCyborg("info", fmt.Sprintf("Starting cross-account log group discovery for %d customer AWS accounts: %v", len(awsAccountIds), awsAccountIds))

	successCount := 0
	failureCount := 0
	for _, awsAccountId := range awsAccountIds {
		fmt.Printf("[LOG_DISCOVERY_CROSS_ACCOUNT] Processing AWS account: %s\n", awsAccountId)
		os.Stdout.Sync()
		utils.LogToCyborg("info", fmt.Sprintf("Processing AWS account: %s", awsAccountId))

		// Assume role in customer account
		fmt.Printf("[LOG_DISCOVERY_CROSS_ACCOUNT] Calling AssumeRoleAndCreateLogsClient for %s\n", awsAccountId)
		os.Stdout.Sync()
		crossAccountLogsClient, err := AssumeRoleAndCreateLogsClient(ctx, stsClient, cfg, awsAccountId)
		if err != nil {
			fmt.Printf("[LOG_DISCOVERY_CROSS_ACCOUNT] ERROR: AssumeRole failed for %s: %v\n", awsAccountId, err)
			os.Stdout.Sync()
			utils.LogToCyborg("error", fmt.Sprintf("Error assuming role for account %s, skipping: %v", awsAccountId, err))
			failureCount++
			continue
		}
		fmt.Printf("[LOG_DISCOVERY_CROSS_ACCOUNT] AssumeRole succeeded for %s\n", awsAccountId)
		os.Stdout.Sync()

		// Discover log groups in customer account
		fmt.Printf("[LOG_DISCOVERY_CROSS_ACCOUNT] Calling DiscoverLogGroupsFromAccount for %s\n", awsAccountId)
		os.Stdout.Sync()
		discovered, err := DiscoverLogGroupsFromAccount(ctx, nil, crossAccountLogsClient, awsAccountId)
		if err != nil {
			fmt.Printf("[LOG_DISCOVERY_CROSS_ACCOUNT] ERROR: DiscoverLogGroupsFromAccount failed for %s: %v\n", awsAccountId, err)
			os.Stdout.Sync()
			utils.LogToCyborg("error", fmt.Sprintf("Error discovering log groups in account %s: %v", awsAccountId, err))
			failureCount++
			continue
		}

		fmt.Printf("[LOG_DISCOVERY_CROSS_ACCOUNT] DiscoverLogGroupsFromAccount returned %d groups for %s\n", len(discovered), awsAccountId)
		os.Stdout.Sync()

		if len(discovered) == 0 {
			fmt.Printf("[LOG_DISCOVERY_CROSS_ACCOUNT] No API Gateway log groups found in account %s\n", awsAccountId)
			os.Stdout.Sync()
			utils.LogToCyborg("info", fmt.Sprintf("No API Gateway log groups found in account %s", awsAccountId))
		} else {
			successCount++
			allDiscovered = append(allDiscovered, discovered...)
			fmt.Printf("[LOG_DISCOVERY_CROSS_ACCOUNT] Successfully discovered %d log groups from account %s\n", len(discovered), awsAccountId)
			for _, lg := range discovered {
				fmt.Printf("[LOG_DISCOVERY_CROSS_ACCOUNT]   - %s\n", lg.Name)
			}
			os.Stdout.Sync()
			utils.LogToCyborg("info", fmt.Sprintf("Successfully discovered %d log groups from account %s", len(discovered), awsAccountId))
		}
	}

	fmt.Printf("[LOG_DISCOVERY_CROSS_ACCOUNT] Cross-account discovery complete: %d successful, %d failed, %d total log groups discovered\n", successCount, failureCount, len(allDiscovered))
	os.Stdout.Sync()
	utils.LogToCyborg("info", fmt.Sprintf("Cross-account discovery complete: %d successful, %d failed, %d total log groups discovered", successCount, failureCount, len(allDiscovered)))
	return allDiscovered, nil
}

func listRestAPIIds(ctx context.Context, client *apigateway.Client) ([]string, error) {
	var ids []string
	paginator := apigateway.NewGetRestApisPaginator(client, &apigateway.GetRestApisInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			utils.LogToCyborg("error", "Error listing REST API IDs: "+err.Error())
			return nil, err
		}
		for _, api := range page.Items {
			if api.Id != nil && *api.Id != "" {
				ids = append(ids, *api.Id)
			}
		}
	}
	return ids, nil
}

func strPtr(s string) *string { return &s }
