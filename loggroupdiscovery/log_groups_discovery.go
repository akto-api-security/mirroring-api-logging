package loggroupdiscovery

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
)

const ApiGatewayExecutionLogGroupPrefix = "API-Gateway-Execution-Logs_"

// GetExecutionLogGroupNames returns CloudWatch log group names that are API Gateway
// execution log groups for REST APIs present in the account. It lists REST API IDs from
// API Gateway, lists log groups with prefix API-Gateway-Execution-Logs_, and keeps only
// those whose name contains a listed API ID.
func GetExecutionLogGroupNames(
	ctx context.Context,
	restClient *apigateway.Client,
	logsClient *cloudwatchlogs.Client,
) ([]string, error) {
	apiIDs, err := listRestAPIIds(ctx, restClient)
	if err != nil {
		return nil, err
	}
	if len(apiIDs) == 0 {
		return nil, nil
	}

	var names []string
	paginator := cloudwatchlogs.NewDescribeLogGroupsPaginator(logsClient, &cloudwatchlogs.DescribeLogGroupsInput{
		LogGroupNamePrefix: strPtr(ApiGatewayExecutionLogGroupPrefix),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
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
					names = append(names, name)
					break
				}
			}
		}
	}
	return names, nil
}

func listRestAPIIds(ctx context.Context, client *apigateway.Client) ([]string, error) {
	var ids []string
	paginator := apigateway.NewGetRestApisPaginator(client, &apigateway.GetRestApisInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
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
