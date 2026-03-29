package loggroupdiscovery

import (
	"context"
	"fmt"
	"strings"

	"github.com/akto-api-security/api-gateway-logging/trafficUtil/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// DiscoveredLogGroup represents a discovered log group with its AWS account ID
type DiscoveredLogGroup struct {
	Name        string
	AwsAccountId string
}

// AssumeRoleAndCreateLogsClient assumes a role in the target AWS account and returns a CloudWatch Logs client
func AssumeRoleAndCreateLogsClient(ctx context.Context, stsClient *sts.Client, cfg aws.Config, targetAwsAccountId string) (*cloudwatchlogs.Client, error) {
	roleArn := fmt.Sprintf("arn:aws:iam::%s:role/AktoLogReaderRole", targetAwsAccountId)
	utils.LogToCyborg("info", fmt.Sprintf("Attempting to assume role: %s", roleArn))

	assumeRoleOutput, err := stsClient.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleArn),
		RoleSessionName: aws.String("AktoLogReader"),
	})
	if err != nil {
		utils.LogToCyborg("error", fmt.Sprintf("Failed to assume role %s: %v (check if role exists, has correct permissions, and trusts this account)", roleArn, err))
		return nil, err
	}

	utils.LogToCyborg("info", fmt.Sprintf("Successfully assumed role. Credentials valid until: %v", assumeRoleOutput.Credentials.Expiration))

	// Create credentials from the assumed role
	staticCreds := credentials.NewStaticCredentialsProvider(
		*assumeRoleOutput.Credentials.AccessKeyId,
		*assumeRoleOutput.Credentials.SecretAccessKey,
		*assumeRoleOutput.Credentials.SessionToken,
	)
	credCache := aws.NewCredentialsCache(staticCreds)

	// Create a new config with the assumed role credentials
	crossAccountCfg := cfg.Copy()
	crossAccountCfg.Credentials = credCache

	// Create CloudWatch Logs client with cross-account credentials
	logsClient := cloudwatchlogs.NewFromConfig(crossAccountCfg)
	utils.LogToCyborg("info", fmt.Sprintf("Created CloudWatch Logs client for cross-account AWS account %s", targetAwsAccountId))
	return logsClient, nil
}

// DiscoverLogGroupsFromAccount lists API Gateway log groups from a specific AWS account
func DiscoverLogGroupsFromAccount(
	ctx context.Context,
	restClient interface{}, // Will be nil for cross-account, used only in single-account
	logsClient *cloudwatchlogs.Client,
	awsAccountId string,
) ([]DiscoveredLogGroup, error) {
	var discovered []DiscoveredLogGroup
	utils.LogToCyborg("info", fmt.Sprintf("Starting DescribeLogGroups API call for account %s with prefix: %s", awsAccountId, ApiGatewayExecutionLogGroupPrefix))

	paginator := cloudwatchlogs.NewDescribeLogGroupsPaginator(logsClient, &cloudwatchlogs.DescribeLogGroupsInput{
		LogGroupNamePrefix: strPtr(ApiGatewayExecutionLogGroupPrefix),
	})

	pageCount := 0
	totalLogGroups := 0
	for paginator.HasMorePages() {
		pageCount++
		page, err := paginator.NextPage(ctx)
		if err != nil {
			utils.LogToCyborg("error", fmt.Sprintf("Error describing log groups in account %s (page %d): %s", awsAccountId, pageCount, err.Error()))
			return nil, err
		}

		totalLogGroups += len(page.LogGroups)
		utils.LogToCyborg("info", fmt.Sprintf("Page %d: received %d log groups from account %s", pageCount, len(page.LogGroups), awsAccountId))

		for _, lg := range page.LogGroups {
			if lg.LogGroupName == nil {
				continue
			}
			name := strings.TrimSpace(*lg.LogGroupName)
			if strings.HasPrefix(name, ApiGatewayExecutionLogGroupPrefix) {
				discovered = append(discovered, DiscoveredLogGroup{
					Name:        name,
					AwsAccountId: awsAccountId,
				})
				utils.LogToCyborg("info", fmt.Sprintf("Discovered API Gateway log group in AWS account %s: %s", awsAccountId, name))
			}
		}
	}

	utils.LogToCyborg("info", fmt.Sprintf("DescribeLogGroups completed for account %s: %d pages, %d total log groups received, %d API Gateway logs found", awsAccountId, pageCount, totalLogGroups, len(discovered)))
	return discovered, nil
}
