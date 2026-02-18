package openapiprocessor

import (
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
)

// CreateAPIGatewayClients creates both REST and HTTP API Gateway clients
// Uses default AWS credentials (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN)
// No role assumption needed for single-account deployments
func CreateAPIGatewayClients(cfg aws.Config) (*ClientSet, error) {
	// Create both API Gateway client types using the default configuration
	clientSet := &ClientSet{
		RestClient: apigateway.NewFromConfig(cfg),    // For REST APIs (v1)
		HttpClient: apigatewayv2.NewFromConfig(cfg), // For HTTP APIs (v2)
	}

	log.Printf("Created API Gateway clients (REST + HTTP) for default AWS account")
	return clientSet, nil
}
