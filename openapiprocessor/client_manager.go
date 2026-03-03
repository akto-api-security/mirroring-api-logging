package openapiprocessor

import (
	"log"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// CreateAPIGatewayClients creates both REST and HTTP API Gateway clients
// Uses default AWS credentials (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN)
// No role assumption needed for single-account deployments
func CreateAPIGatewayClients(cfg aws.Config) (*ClientSet, error) {
	clientSet := &ClientSet{
		RestClient: apigateway.NewFromConfig(cfg),
		HttpClient: apigatewayv2.NewFromConfig(cfg),
	}
	log.Printf("Created API Gateway clients (REST + HTTP) for default AWS account")
	return clientSet, nil
}

// CreateAPIGatewayClientsFromRole creates REST + HTTP API Gateway clients using STS AssumeRole for the given roleArn.
func CreateAPIGatewayClientsFromRole(cfg aws.Config, stsSvc *sts.Client, roleArn string, sessionName string) (*ClientSet, error) {
	roleArn = strings.TrimSpace(roleArn)
	if roleArn == "" {
		return nil, nil
	}
	roleCfg := cfg.Copy()
	creds := stscreds.NewAssumeRoleProvider(stsSvc, roleArn, func(o *stscreds.AssumeRoleOptions) {
		o.RoleSessionName = sessionName
	})
	roleCfg.Credentials = aws.NewCredentialsCache(creds)
	clientSet := &ClientSet{
		RestClient: apigateway.NewFromConfig(roleCfg),
		HttpClient: apigatewayv2.NewFromConfig(roleCfg),
	}
	log.Printf("Created API Gateway clients for role: %s", roleArn)
	return clientSet, nil
}
