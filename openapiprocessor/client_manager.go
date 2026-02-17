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

// CreateAPIGatewayClients creates both REST and HTTP API Gateway clients for a role
// Mirrors main.go's createArnClient pattern (lines 255-276)
func CreateAPIGatewayClients(
	roleArn string,
	cfg aws.Config,
	stsSvc *sts.Client,
	sessionName string,
) (*ClientSet, error) {
	roleArn = strings.TrimSpace(roleArn)
	if roleArn == "" {
		return nil, nil
	}

	// Create role-specific configuration
	roleCfg := cfg.Copy()

	// Temporary credentials for this role using STS AssumeRole
	creds := stscreds.NewAssumeRoleProvider(stsSvc, roleArn, func(o *stscreds.AssumeRoleOptions) {
		o.RoleSessionName = sessionName
	})

	roleCfg.Credentials = aws.NewCredentialsCache(creds)

	// Create both API Gateway client types
	clientSet := &ClientSet{
		RestClient: apigateway.NewFromConfig(roleCfg),  // For REST APIs (v1)
		HttpClient: apigatewayv2.NewFromConfig(roleCfg), // For HTTP APIs (v2)
	}

	log.Printf("Created API Gateway clients (REST + HTTP) for role: %s", roleArn)
	return clientSet, nil
}
