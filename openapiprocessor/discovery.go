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

// MonitorAPIs runs one OpenAPI discovery cycle for the given clientSet and role, then returns.
// Main is responsible for calling this on an interval (e.g. OPENAPI_DISCOVERY_INTERVAL_MINUTES).
func MonitorAPIs(
	ctx context.Context,
	clientSet *ClientSet,
	roleArn string,
	region string,
	authToken string,
) {
	utils.LogToCyborg("info", "Starting OpenAPI discovery cycle for role: "+roleArn)

	// Discover REST APIs (v1)
	if clientSet.RestClient == nil {
		utils.LogToCyborg("warn", "REST API client not available, skipping REST API discovery")
	}
	if clientSet.RestClient != nil {
		if err := discoverRESTAPIs(ctx, clientSet.RestClient, roleArn, region, authToken); err != nil {
			utils.LogToCyborg("error", "Error discovering REST APIs for "+roleArn+": "+err.Error())
		}
	}

	// Discover HTTP APIs (v2)
	if clientSet.HttpClient == nil {
		utils.LogToCyborg("warn", "HTTP API client not available, skipping HTTP API discovery")
	}
	if clientSet.HttpClient != nil {
		if err := discoverHTTPAPIs(ctx, clientSet.HttpClient, roleArn, region, authToken); err != nil {
			utils.LogToCyborg("error", "Error discovering HTTP APIs for "+roleArn+": "+err.Error())
		}
	}

	utils.LogToCyborg("info", "Completed OpenAPI discovery cycle for role: "+roleArn)
}

// discoverRESTAPIs discovers all REST APIs and their stages
func discoverRESTAPIs(
	ctx context.Context,
	client *apigateway.Client,
	roleArn string,
	region string,
	authToken string,
) error {
	utils.LogToCyborg("info", "Discovering REST APIs for role: "+roleArn)

	// List all REST APIs with pagination
	paginator := apigateway.NewGetRestApisPaginator(client, &apigateway.GetRestApisInput{})

	apiCount := 0
	stageCount := 0

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			utils.LogToCyborg("error", "Error fetching REST APIs page: "+err.Error())
			return err
		}

		for _, api := range page.Items {
			if api.Id == nil || api.Name == nil {
				continue
			}

			apiCount++
			utils.LogToCyborg("info", "Found REST API: "+*api.Name+" (ID: "+*api.Id+")")

			// Get stages for this API
			stages, err := client.GetStages(ctx, &apigateway.GetStagesInput{
				RestApiId: api.Id,
			})

			if err != nil {
				utils.LogToCyborg("error", "Error fetching stages for API "+*api.Id+": "+err.Error())
				continue // Continue to next API
			}

			// Export spec for each stage
			for _, stage := range stages.Item {
				if stage.StageName == nil {
					continue
				}

				stageCount++
				utils.LogLocal("info", fmt.Sprintf("Exporting spec for API %s stage %s", *api.Id, *stage.StageName))

				// Export OpenAPI spec for this stage
				spec, err := client.GetExport(ctx, &apigateway.GetExportInput{
					RestApiId:  api.Id,
					StageName:  stage.StageName,
					ExportType: aws.String(EXPORT_FORMAT_OAS30),
					Accepts:    aws.String("application/json"),
				})

				if err != nil {
					utils.LogToCyborg("error", "Error exporting spec for API "+*api.Id+" stage "+*stage.StageName+": "+err.Error())
					continue // Continue to next stage
				}

				// Check if spec changed (deduplication)
				if shouldSendSpec(roleArn, *api.Id, *stage.StageName, spec.Body) {
					utils.LogToCyborg("info", "Spec changed for API "+*api.Id+" stage "+*stage.StageName+", uploading")
					// Upload to dashboard
					if err := uploadOpenAPISpecToCyborg(spec.Body, *api.Name, *api.Id, roleArn, region, *stage.StageName, authToken); err != nil {
						utils.LogToCyborg("error", "Error uploading spec for API "+*api.Id+" stage "+*stage.StageName+": "+err.Error())
						GetTracker().RemoveDiscoveredAPICache(roleArn, *api.Id, *stage.StageName)
					}
				} else {
					utils.LogLocal("info", fmt.Sprintf("Spec unchanged for API %s stage %s, skipping", *api.Id, *stage.StageName))
				}
			}
		}
	}

	utils.LogToCyborg("info", fmt.Sprintf("Discovered %d REST APIs with %d stages total", apiCount, stageCount))
	return nil
}

// discoverHTTPAPIs discovers all HTTP APIs (v2)
func discoverHTTPAPIs(
	ctx context.Context,
	client *apigatewayv2.Client,
	roleArn string,
	region string,
	authToken string,
) error {
	utils.LogToCyborg("info", "Discovering HTTP APIs for role: "+roleArn)

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
			utils.LogToCyborg("error", "Error fetching HTTP APIs page: "+err.Error())
			return err
		}

		for _, api := range page.Items {
			if api.ApiId == nil || api.Name == nil {
				continue
			}

			apiCount++
			utils.LogToCyborg("info", "Found HTTP API: "+*api.Name+" (ID: "+*api.ApiId+")")

			// Export OpenAPI spec (HTTP APIs don't have stages)
			spec, err := client.ExportApi(ctx, &apigatewayv2.ExportApiInput{
				ApiId:         api.ApiId,
				OutputType:    aws.String("JSON"),
				Specification: aws.String("OAS30"),
			})

			if err != nil {
				utils.LogToCyborg("error", "Error exporting spec for HTTP API "+*api.ApiId+": "+err.Error())
				continue // Continue to next API
			}

			// Check if spec changed (deduplication) - empty stage for HTTP APIs
			if shouldSendSpec(roleArn, *api.ApiId, "", spec.Body) {
				utils.LogToCyborg("info", "Spec changed for HTTP API "+*api.ApiId+", uploading")
				// Upload to dashboard
				if err := uploadOpenAPISpecToCyborg(spec.Body, *api.Name, *api.ApiId, roleArn, region, "", authToken); err != nil {
					utils.LogToCyborg("error", "Error uploading spec for HTTP API "+*api.ApiId+": "+err.Error())
					GetTracker().RemoveDiscoveredAPICache(roleArn, *api.ApiId, "")
				}
			} else {
				utils.LogLocal("info", fmt.Sprintf("Spec unchanged for HTTP API %s, skipping", *api.ApiId))
			}
		}

		// Check if there are more pages
		if page.NextToken == nil || *page.NextToken == "" {
			break
		}
		nextToken = page.NextToken
	}

	utils.LogToCyborg("info", fmt.Sprintf("Discovered %d HTTP APIs", apiCount))
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
