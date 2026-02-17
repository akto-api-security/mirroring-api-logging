package openapiprocessor

import (
	"context"
	"crypto/md5"
	"fmt"
	"time"

	"github.com/akto-api-security/api-gateway-logging/trafficUtil/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
)

// MonitorAPIs discovers API Gateway specs across configured role
// Called as goroutine from main.go (similar to logprocesser.MonitorLogGroup)
// This runs in an infinite loop with DISCOVERY_POLL_DURATION sleep
func MonitorAPIs(
	ctx context.Context,
	clientSet *ClientSet,
	roleArn string,
	region string,
) {
	for {
		utils.DebugLog("Starting OpenAPI discovery cycle for role: %s", roleArn)

		// Discover REST APIs (v1)
		if clientSet.RestClient != nil {
			if err := discoverRESTAPIs(ctx, clientSet.RestClient, roleArn, region); err != nil {
				utils.DebugLog("Error discovering REST APIs for %s: %v", roleArn, err)
			}
		}

		// Discover HTTP APIs (v2)
		if clientSet.HttpClient != nil {
			if err := discoverHTTPAPIs(ctx, clientSet.HttpClient, roleArn, region); err != nil {
				utils.DebugLog("Error discovering HTTP APIs for %s: %v", roleArn, err)
			}
		}

		utils.DebugLog("Completed OpenAPI discovery cycle for role: %s", roleArn)

		// Sleep until next discovery cycle
		time.Sleep(DISCOVERY_POLL_DURATION)
	}
}

// discoverRESTAPIs discovers all REST APIs and their stages
func discoverRESTAPIs(
	ctx context.Context,
	client *apigateway.Client,
	roleArn string,
	region string,
) error {
	utils.DebugLog("Discovering REST APIs for role: %s", roleArn)

	// List all REST APIs with pagination
	paginator := apigateway.NewGetRestApisPaginator(client, &apigateway.GetRestApisInput{})

	apiCount := 0
	stageCount := 0

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			utils.DebugLog("Error fetching REST APIs page: %v", err)
			return err
		}

		for _, api := range page.Items {
			if api.Id == nil || api.Name == nil {
				continue
			}

			apiCount++
			utils.DebugLog("Found REST API: %s (ID: %s)", *api.Name, *api.Id)

			// Get stages for this API
			stages, err := client.GetStages(ctx, &apigateway.GetStagesInput{
				RestApiId: api.Id,
			})

			if err != nil {
				utils.DebugLog("Error fetching stages for API %s: %v", *api.Id, err)
				continue // Continue to next API
			}

			// Export spec for each stage
			for _, stage := range stages.Item {
				if stage.StageName == nil {
					continue
				}

				stageCount++
				utils.DebugLog("Exporting spec for API %s stage %s", *api.Id, *stage.StageName)

				// Export OpenAPI spec for this stage
				spec, err := client.GetExport(ctx, &apigateway.GetExportInput{
					RestApiId:  api.Id,
					StageName:  stage.StageName,
					ExportType: aws.String(EXPORT_FORMAT_OAS30),
					Accepts:    aws.String("application/json"),
				})

				if err != nil {
					utils.DebugLog("Error exporting spec for API %s stage %s: %v", *api.Id, *stage.StageName, err)
					continue // Continue to next stage
				}

				// Check if spec changed (deduplication)
				if shouldSendSpec(roleArn, *api.Id, *stage.StageName, spec.Body) {
					utils.DebugLog("Spec changed for API %s stage %s, sending to Kafka", *api.Id, *stage.StageName)
					// Parse and send to Kafka
					if err := parseAndSendOpenAPISpec(spec.Body, *api.Name, roleArn, region, *stage.StageName); err != nil {
						utils.DebugLog("Error parsing/sending spec for API %s stage %s: %v", *api.Id, *stage.StageName, err)
					}
				} else {
					utils.DebugLog("Spec unchanged for API %s stage %s, skipping", *api.Id, *stage.StageName)
				}
			}
		}
	}

	utils.DebugLog("Discovered %d REST APIs with %d stages total", apiCount, stageCount)
	return nil
}

// discoverHTTPAPIs discovers all HTTP APIs (v2)
func discoverHTTPAPIs(
	ctx context.Context,
	client *apigatewayv2.Client,
	roleArn string,
	region string,
) error {
	utils.DebugLog("Discovering HTTP APIs for role: %s", roleArn)

	// List all HTTP APIs with manual pagination (no paginator available)
	apiCount := 0
	var nextToken *string = nil

	for {
		input := &apigatewayv2.GetApisInput{}
		if nextToken != nil {
			input.NextToken = nextToken
		}

		page, err := client.GetApis(ctx, input)
		if err != nil {
			utils.DebugLog("Error fetching HTTP APIs page: %v", err)
			return err
		}

		for _, api := range page.Items {
			if api.ApiId == nil || api.Name == nil {
				continue
			}

			apiCount++
			utils.DebugLog("Found HTTP API: %s (ID: %s)", *api.Name, *api.ApiId)

			// Export OpenAPI spec (HTTP APIs don't have stages)
			spec, err := client.ExportApi(ctx, &apigatewayv2.ExportApiInput{
				ApiId:         api.ApiId,
				OutputType:    aws.String("JSON"),
				Specification: aws.String("OAS30"),
			})

			if err != nil {
				utils.DebugLog("Error exporting spec for HTTP API %s: %v", *api.ApiId, err)
				continue // Continue to next API
			}

			// Check if spec changed (deduplication) - empty stage for HTTP APIs
			if shouldSendSpec(roleArn, *api.ApiId, "", spec.Body) {
				utils.DebugLog("Spec changed for HTTP API %s, sending to Kafka", *api.ApiId)
				// Parse and send to Kafka
				if err := parseAndSendOpenAPISpec(spec.Body, *api.Name, roleArn, region, ""); err != nil {
					utils.DebugLog("Error parsing/sending spec for HTTP API %s: %v", *api.ApiId, err)
				}
			} else {
				utils.DebugLog("Spec unchanged for HTTP API %s, skipping", *api.ApiId)
			}
		}

		// Check if there are more pages
		if page.NextToken == nil || *page.NextToken == "" {
			break
		}
		nextToken = page.NextToken
	}

	utils.DebugLog("Discovered %d HTTP APIs", apiCount)
	return nil
}

// shouldSendSpec checks if the spec has changed since last discovery
// Returns true if this is a new API or the spec content changed
func shouldSendSpec(roleArn, apiID, stage string, specContent []byte) bool {
	key := fmt.Sprintf("%s|%s|%s", roleArn, apiID, stage)
	checksum := fmt.Sprintf("%x", md5.Sum(specContent))

	tracker := GetTracker()
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	existing, exists := tracker.discoveredAPIs[key]
	if !exists || existing.SpecChecksum != checksum {
		// New or changed spec - update tracker
		tracker.discoveredAPIs[key] = &DiscoveredAPI{
			APIID:          apiID,
			Stage:          stage,
			SpecChecksum:   checksum,
			LastDiscovered: time.Now().Unix(),
		}
		return true
	}

	// Update last discovered time even if unchanged
	existing.LastDiscovered = time.Now().Unix()
	return false // No change, skip
}
