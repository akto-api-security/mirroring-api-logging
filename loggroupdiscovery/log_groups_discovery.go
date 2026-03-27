package loggroupdiscovery

import (
	"context"
	"fmt"
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
	if crossAccountMode {
		return discoverLogGroupsCrossAccount(ctx, logsClient, stsClient, cfg)
	}
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
	// Get all AWS account IDs from account mappings
	mappings := accountconfig.GetAllMappings()
	if len(mappings) == 0 {
		utils.LogToCyborg("warn", "Cross-account mode enabled but no AWS account mappings found")
		return nil, nil
	}

	var allDiscovered []DiscoveredLogGroup
	var awsAccountIds []string
	for awsAccountId := range mappings {
		awsAccountIds = append(awsAccountIds, awsAccountId)
	}

	utils.LogToCyborg("info", fmt.Sprintf("Discovering log groups from %d customer AWS accounts", len(awsAccountIds)))

	for _, awsAccountId := range awsAccountIds {
		// Assume role in customer account
		crossAccountLogsClient, err := AssumeRoleAndCreateLogsClient(ctx, stsClient, cfg, awsAccountId)
		if err != nil {
			utils.LogToCyborg("error", fmt.Sprintf("Error assuming role for account %s, skipping: %v", awsAccountId, err))
			continue
		}

		// Discover log groups in customer account
		discovered, err := DiscoverLogGroupsFromAccount(ctx, nil, crossAccountLogsClient, awsAccountId)
		if err != nil {
			utils.LogToCyborg("error", fmt.Sprintf("Error discovering log groups in account %s: %v", awsAccountId, err))
			continue
		}

		allDiscovered = append(allDiscovered, discovered...)
	}

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
