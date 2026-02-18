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

// uploadOpenAPISpecToDashboard uploads the raw OpenAPI spec to Akto dashboard
// and completes the full workflow: upload -> poll status -> import
func uploadOpenAPISpecToDashboard(
	specContent []byte,
	apiName string,
	apiId string,
	roleArn string,
	region string,
	stage string,
	dashboardURL string,
	aktoToken string,
) error {
	utils.DebugLog("Uploading OpenAPI spec for API: %s (ID: %s, stage: %s) to dashboard", apiName, apiId, stage)

	// Step 1: Upload the OpenAPI spec
	uploadID, err := uploadSpec(specContent, dashboardURL, aktoToken)
	if err != nil {
		return fmt.Errorf("failed to upload spec: %v", err)
	}

	utils.DebugLog("✓ Spec uploaded successfully with uploadId: %s", uploadID)

	// Step 2: Poll for upload completion
	if err := pollUploadStatus(uploadID, dashboardURL, aktoToken); err != nil {
		return fmt.Errorf("failed to poll upload status: %v", err)
	}

	utils.DebugLog("✓ Spec processing completed for uploadId: %s", uploadID)

	// Step 3: Import the processed spec
	if err := importSpec(uploadID, dashboardURL, aktoToken); err != nil {
		return fmt.Errorf("failed to import spec: %v", err)
	}

	utils.DebugLog("✓ Successfully completed full workflow for API %s (stage: %s)", apiName, stage)
	return nil
}

// uploadSpec uploads the OpenAPI spec and returns the uploadId
func uploadSpec(specContent []byte, dashboardURL string, aktoToken string) (string, error) {
	endpoint := fmt.Sprintf("%s/api/importDataFromOpenApiSpec", dashboardURL)

	// Create request payload
	payload := map[string]string{
		"openAPIString": string(specContent),
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(payloadJSON))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-KEY", aktoToken)

	// Send request
	client := &http.Client{
		Timeout: 60 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %v", err)
	}

	// Check response status
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse uploadId from response
	var result struct {
		UploadID string `json:"uploadId"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to parse uploadId from response: %v", err)
	}

	if result.UploadID == "" {
		return "", fmt.Errorf("uploadId not found in response: %s", string(body))
	}

	return result.UploadID, nil
}

// pollUploadStatus polls the upload status until it's SUCCEEDED or failed
func pollUploadStatus(uploadID string, dashboardURL string, aktoToken string) error {
	endpoint := fmt.Sprintf("%s/api/fetchSwaggerImportLogs", dashboardURL)

	// Create request payload
	payload := map[string]string{
		"uploadId": uploadID,
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Poll with exponential backoff (max 5 minutes total)
	maxAttempts := 60               // 60 attempts
	pollInterval := 5 * time.Second // Start with 5 seconds
	maxPollInterval := 30 * time.Second

	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Create HTTP request
		req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(payloadJSON))
		if err != nil {
			return fmt.Errorf("failed to create request: %v", err)
		}

		// Set headers
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-KEY", aktoToken)

		// Send request
		resp, err := client.Do(req)
		if err != nil {
			utils.DebugLog("Error polling upload status (attempt %d): %v", attempt+1, err)
			time.Sleep(pollInterval)
			continue
		}

		// Read response
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if err != nil {
			utils.DebugLog("Error reading response (attempt %d): %v", attempt+1, err)
			time.Sleep(pollInterval)
			continue
		}

		// Check response status
		if resp.StatusCode != http.StatusOK {
			utils.DebugLog("API returned status %d (attempt %d): %s", resp.StatusCode, attempt+1, string(body))
			time.Sleep(pollInterval)
			continue
		}

		// Parse response
		var result struct {
			UploadDetails struct {
				UploadStatus                      string   `json:"uploadStatus"`
				CollectionErrors                  []string `json:"collectionErrors"`
				Logs                              []string `json:"logs"`
				APIsWithErrorsAndParsed           int      `json:"apisWithErrorsAndParsed"`
				APIsWithErrorsAndCannotBeImported int      `json:"apisWithErrorsAndCannotBeImported"`
				CorrectlyParsedAPIs               int      `json:"correctlyParsedApis"`
				TotalCount                        int      `json:"totalCount"`
			} `json:"uploadDetails"`
			UploadID string `json:"uploadId"`
		}

		if err := json.Unmarshal(body, &result); err != nil {
			utils.DebugLog("Failed to parse response (attempt %d): %v", attempt+1, err)
			time.Sleep(pollInterval)
			continue
		}

		// Check upload status
		status := result.UploadDetails.UploadStatus
		utils.DebugLog("Upload status (attempt %d): %s - Parsed: %d/%d APIs",
			attempt+1, status, result.UploadDetails.CorrectlyParsedAPIs, result.UploadDetails.TotalCount)

		if status == "SUCCEEDED" {
			utils.DebugLog("✓ Upload completed successfully: %d APIs parsed", result.UploadDetails.CorrectlyParsedAPIs)
			return nil
		}

		if status == "FAILED" {
			return fmt.Errorf("upload failed: errors=%v", result.UploadDetails.CollectionErrors)
		}

		// Status is still in progress (e.g., "PROCESSING", "IN_PROGRESS", etc.)
		// Sleep and retry with exponential backoff
		time.Sleep(pollInterval)

		// Increase poll interval (exponential backoff)
		if pollInterval < maxPollInterval {
			pollInterval = pollInterval * 2
			if pollInterval > maxPollInterval {
				pollInterval = maxPollInterval
			}
		}
	}

	return fmt.Errorf("timeout waiting for upload to complete after %d attempts", maxAttempts)
}

// importSpec triggers the final import of the processed spec
func importSpec(uploadID string, dashboardURL string, aktoToken string) error {
	endpoint := fmt.Sprintf("%s/api/importSwaggerLogs", dashboardURL)

	// Create request payload
	payload := map[string]string{
		"uploadId":   uploadID,
		"importType": "ALL_APIS",
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(payloadJSON))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-KEY", aktoToken)

	// Send request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %v", err)
	}

	// Check response status
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	utils.DebugLog("Import API response: %s", string(body))
	return nil
}
