package loggroupdiscovery

import (
	"context"
	"fmt"
	"os"
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
	fmt.Printf("[ASSUME_ROLE] Starting AssumeRoleAndCreateLogsClient for account: %s\n", targetAwsAccountId)
	os.Stdout.Sync()

	roleArn := fmt.Sprintf("arn:aws:iam::%s:role/AktoReadOnlyIntegrationRole", targetAwsAccountId)
	fmt.Printf("[ASSUME_ROLE] Role ARN: %s\n", roleArn)
	os.Stdout.Sync()
	utils.LogToCyborg("info", fmt.Sprintf("Attempting to assume role: %s", roleArn))

	fmt.Printf("[ASSUME_ROLE] Calling stsClient.AssumeRole() for %s\n", targetAwsAccountId)
	os.Stdout.Sync()

	assumeRoleOutput, err := stsClient.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleArn),
		RoleSessionName: aws.String("AktoLogReader"),
	})
	if err != nil {
		fmt.Printf("[ASSUME_ROLE] ERROR: AssumeRole failed for %s: %v\n", targetAwsAccountId, err)
		os.Stdout.Sync()
		utils.LogToCyborg("error", fmt.Sprintf("Failed to assume role %s: %v (check if role exists, has correct permissions, and trusts this account)", roleArn, err))
		return nil, err
	}

	fmt.Printf("[ASSUME_ROLE] AssumeRole succeeded for %s. Credentials valid until: %v\n", targetAwsAccountId, assumeRoleOutput.Credentials.Expiration)
	os.Stdout.Sync()
	utils.LogToCyborg("info", fmt.Sprintf("Successfully assumed role. Credentials valid until: %v", assumeRoleOutput.Credentials.Expiration))

	// Create credentials from the assumed role
	fmt.Println("[ASSUME_ROLE] Creating static credentials from assumed role")
	os.Stdout.Sync()
	staticCreds := credentials.NewStaticCredentialsProvider(
		*assumeRoleOutput.Credentials.AccessKeyId,
		*assumeRoleOutput.Credentials.SecretAccessKey,
		*assumeRoleOutput.Credentials.SessionToken,
	)
	credCache := aws.NewCredentialsCache(staticCreds)

	// Create a new config with the assumed role credentials
	fmt.Println("[ASSUME_ROLE] Creating cross-account AWS config")
	os.Stdout.Sync()
	crossAccountCfg := cfg.Copy()
	crossAccountCfg.Credentials = credCache

	// Create CloudWatch Logs client with cross-account credentials
	fmt.Printf("[ASSUME_ROLE] Creating CloudWatch Logs client for account %s\n", targetAwsAccountId)
	os.Stdout.Sync()
	logsClient := cloudwatchlogs.NewFromConfig(crossAccountCfg)
	fmt.Printf("[ASSUME_ROLE] CloudWatch Logs client created successfully for account %s\n", targetAwsAccountId)
	os.Stdout.Sync()
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
	fmt.Printf("[DISCOVER_LOGS] Starting DiscoverLogGroupsFromAccount for account: %s\n", awsAccountId)
	os.Stdout.Sync()

	var discovered []DiscoveredLogGroup
	fmt.Printf("[DISCOVER_LOGS] Creating paginator with prefix: %s\n", ApiGatewayExecutionLogGroupPrefix)
	os.Stdout.Sync()
	utils.LogToCyborg("info", fmt.Sprintf("Starting DescribeLogGroups API call for account %s with prefix: %s", awsAccountId, ApiGatewayExecutionLogGroupPrefix))

	paginator := cloudwatchlogs.NewDescribeLogGroupsPaginator(logsClient, &cloudwatchlogs.DescribeLogGroupsInput{
		LogGroupNamePrefix: strPtr(ApiGatewayExecutionLogGroupPrefix),
	})

	fmt.Println("[DISCOVER_LOGS] Starting paginator loop")
	os.Stdout.Sync()

	pageCount := 0
	totalLogGroups := 0
	for paginator.HasMorePages() {
		pageCount++
		fmt.Printf("[DISCOVER_LOGS] Fetching page %d\n", pageCount)
		os.Stdout.Sync()

		page, err := paginator.NextPage(ctx)
		if err != nil {
			fmt.Printf("[DISCOVER_LOGS] ERROR on page %d: %v\n", pageCount, err)
			os.Stdout.Sync()
			utils.LogToCyborg("error", fmt.Sprintf("Error describing log groups in account %s (page %d): %s", awsAccountId, pageCount, err.Error()))
			return nil, err
		}

		totalLogGroups += len(page.LogGroups)
		fmt.Printf("[DISCOVER_LOGS] Page %d: received %d log groups (total so far: %d)\n", pageCount, len(page.LogGroups), totalLogGroups)
		os.Stdout.Sync()
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
				fmt.Printf("[DISCOVER_LOGS] Discovered log group: %s\n", name)
				os.Stdout.Sync()
				utils.LogToCyborg("info", fmt.Sprintf("Discovered API Gateway log group in AWS account %s: %s", awsAccountId, name))
			}
		}
	}

	fmt.Printf("[DISCOVER_LOGS] DescribeLogGroups completed for account %s: %d pages, %d total log groups received, %d API Gateway logs found\n",
		awsAccountId, pageCount, totalLogGroups, len(discovered))
	os.Stdout.Sync()
	utils.LogToCyborg("info", fmt.Sprintf("DescribeLogGroups completed for account %s: %d pages, %d total log groups received, %d API Gateway logs found", awsAccountId, pageCount, totalLogGroups, len(discovered)))
	return discovered, nil
}
