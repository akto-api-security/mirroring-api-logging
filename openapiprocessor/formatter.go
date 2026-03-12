package openapiprocessor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/akto-api-security/api-gateway-logging/trafficUtil/utils"
)

// uploadOpenAPISpecToCyborg uploads the raw OpenAPI spec directly to cyborg
// which handles parsing and importing on the backend
func uploadOpenAPISpecToCyborg(
	specContent []byte,
	apiName string,
	apiId string,
	roleArn string,
	region string,
	stage string,
	authToken string,
) error {
	utils.DebugLog("Uploading OpenAPI spec for API: %s (ID: %s, stage: %s) to cyborg", apiName, apiId, stage)

	endpoint := utils.CyborgBaseURL + "/api/importOpenApiSpec"

	// Create request payload
	payload := map[string]string{
		"openApiSchema": string(specContent),
		"importType":    "ALL_APIS",
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		utils.LogToCyborg("error", "Open API Upload Failed: Failed to marshal payload: "+err.Error())
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(payloadJSON))
	if err != nil {
		utils.LogToCyborg("error", "Open API Upload Failed: Failed to create request: "+err.Error())
		return fmt.Errorf("failed to create request: %v", err)
	}

	// Set headers (same pattern as fetchAwsAccountIds in main.go)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("authorization", authToken)

	// Send request
	client := &http.Client{
		Timeout: 60 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		utils.LogToCyborg("error", "Open API Upload Failed: Failed to send request: "+err.Error())
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		utils.LogToCyborg("error", "Open API Upload Failed: Failed to read response: "+err.Error())
		return fmt.Errorf("failed to read response: %v", err)
	}

	// Check response status
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		utils.LogToCyborg("error", "OpenAPI upload failed for API "+apiName+" (id="+apiId+" stage="+stage+"): status "+fmt.Sprint(resp.StatusCode))
		return fmt.Errorf("cyborg API returned status %d: %s", resp.StatusCode, string(body))
	}

	utils.DebugLog("✓ Successfully uploaded OpenAPI spec for API %s (stage: %s) to cyborg. Response: %s", apiName, stage, string(body))
	utils.LogToCyborg("info", "Successfully uploaded OpenAPI spec for API "+apiName+" (stage: "+stage+")")
	return nil
}
