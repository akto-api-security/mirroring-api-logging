package openapiprocessor

import (
	"context"
	"fmt"

	"github.com/akto-api-security/api-gateway-logging/trafficUtil/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
)

// CreateAPIGatewayClients creates both REST and HTTP API Gateway clients
// Uses default AWS credentials (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN)
// or the default credential chain (env, shared config, IAM role, etc.).
// Returns an error if credentials are not present or could not be resolved.
func CreateAPIGatewayClients(cfg aws.Config) (*ClientSet, error) {
	utils.LogToCyborg("info", "Creating API Gateway clients for region: "+cfg.Region)

	if cfg.Credentials == nil {
		return nil, fmt.Errorf("AWS credentials provider is nil; set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY (and AWS_SESSION_TOKEN for temporary credentials), or use IAM role / shared config")
	}
	_, err := cfg.Credentials.Retrieve(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("AWS credentials not available: %w (ensure AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY are set, or use IAM role when running on EC2/ECS/Lambda)", err)
	}

	// Create both API Gateway client types using the default configuration
	clientSet := &ClientSet{
		RestClient: apigateway.NewFromConfig(cfg),   // For REST APIs (v1)
		HttpClient: apigatewayv2.NewFromConfig(cfg), // For HTTP APIs (v2)
	}

	utils.LogToCyborg("info", "Created API Gateway clients (REST + HTTP)")
	return clientSet, nil
}
