package openapiprocessor

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/akto-api-security/api-gateway-logging/trafficUtil/kafkaUtil"
	"github.com/akto-api-security/api-gateway-logging/trafficUtil/utils"
)

// parseAndSendOpenAPISpec parses the OpenAPI spec and creates Kafka messages
// for each endpoint (path + method combination)
func parseAndSendOpenAPISpec(
	specContent []byte,
	apiName string,
	apiId string,
	roleArn string,
	region string,
	stage string,
) error {
	utils.DebugLog("Parsing OpenAPI spec for API: %s (ID: %s, stage: %s, size: %d bytes)", apiName, apiId, stage, len(specContent))

	// Parse OpenAPI JSON
	var spec map[string]interface{}
	if err := json.Unmarshal(specContent, &spec); err != nil {
		utils.DebugLog("ERROR: Failed to parse OpenAPI spec for %s: %v", apiName, err)
		return fmt.Errorf("failed to parse OpenAPI spec: %v", err)
	}

	// Extract paths from OpenAPI spec
	paths, ok := spec["paths"].(map[string]interface{})
	if !ok {
		utils.DebugLog("WARNING: No paths found in OpenAPI spec for %s", apiName)
		return fmt.Errorf("no paths found in OpenAPI spec")
	}

	utils.DebugLog("Found %d paths in OpenAPI spec for %s", len(paths), apiName)

	// Extract host from OpenAPI spec servers or construct from API ID
	defaultHost := extractHostFromSpec(spec, apiId, region)
	utils.DebugLog("Using host: %s for API %s", defaultHost, apiName)

	endpointCount := 0
	successCount := 0
	failedCount := 0
	loggedSample := false

	// For each path and method, create a Kafka message
	for path, pathItem := range paths {
		pathObj, ok := pathItem.(map[string]interface{})
		if !ok {
			utils.DebugLog("WARNING: Skipping invalid path item for %s", path)
			continue
		}

		// Iterate methods (get, post, put, delete, etc.)
		for method, operation := range pathObj {
			if !isHTTPMethod(method) {
				continue // Skip non-method fields like "parameters", "servers", etc.
			}

			operationObj, ok := operation.(map[string]interface{})
			if !ok {
				utils.DebugLog("WARNING: Skipping invalid operation for %s %s", strings.ToUpper(method), path)
				continue
			}

			// Extract request and response schemas
			requestSchema := extractRequestSchema(operationObj)
			responseSchema := extractResponseSchema(operationObj)

			// Use the default host extracted from spec or constructed
			requestHeaders := map[string]string{
				"host": defaultHost,
			}
			requestHeadersJSON, _ := json.Marshal(requestHeaders)

			// Create message in existing traffic log format
			value := map[string]string{
				"path":            path,
				"method":          strings.ToUpper(method),
				"requestHeaders":  string(requestHeadersJSON), // Include host header
				"responseHeaders": "{}",                       // Empty for spec-based discovery
				"requestPayload":  requestSchema,              // JSON schema from OpenAPI
				"responsePayload": responseSchema,             // JSON schema from OpenAPI
				"ip":              "127.0.0.1",
				"time":            fmt.Sprint(time.Now().Unix()),
				"statusCode":      "200", // Default status code
				"type":            "HTTP/1.1",
				"status":          "OK",
				"akto_account_id": fmt.Sprint(1000000),
				"akto_vxlan_id":   fmt.Sprint(0),
				"is_pending":      fmt.Sprint(false),
				"source":          "MIRRORING", // Keep same as traffic logs per user requirement
				"direction":       fmt.Sprint(1),
				"tag":             buildTagJSON(apiName, roleArn, region, stage),
			}

			utils.DebugLog("Sending to Kafka: %s %s (API: %s, stage: %s)", strings.ToUpper(method), path, apiName, stage)

			// Log first message as sample for debugging
			if !loggedSample {
				messageJSON, _ := json.MarshalIndent(value, "", "  ")
				utils.DebugLog("SAMPLE KAFKA MESSAGE:\n%s", string(messageJSON))
				loggedSample = true
			}

			// Send to Kafka using existing utility
			kafkaUtil.ParseAndProduce(value)
			endpointCount++
			successCount++

			utils.DebugLog("✓ Successfully queued Kafka message for %s %s (tag: %s)", strings.ToUpper(method), path, value["tag"])
		}
	}

	if endpointCount > 0 {
		utils.DebugLog("✓ SUMMARY: Sent %d endpoints from API %s (stage: %s) to Kafka - Success: %d, Failed: %d",
			endpointCount, apiName, stage, successCount, failedCount)
	} else {
		utils.DebugLog("WARNING: No endpoints found in API %s (stage: %s)", apiName, stage)
	}

	return nil
}

// extractHostFromSpec extracts the host from OpenAPI spec servers array
// Falls back to constructing from apiId and region if not found
func extractHostFromSpec(spec map[string]interface{}, apiId string, region string) string {
	// Default fallback: construct from API ID and region
	defaultHost := fmt.Sprintf("%s.execute-api.%s.amazonaws.com", apiId, region)

	// Try to extract from servers array
	servers, ok := spec["servers"].([]interface{})
	if !ok || len(servers) == 0 {
		return defaultHost
	}

	// Get the first server URL
	firstServer, ok := servers[0].(map[string]interface{})
	if !ok {
		return defaultHost
	}

	serverURL, ok := firstServer["url"].(string)
	if !ok || serverURL == "" {
		return defaultHost
	}

	// Parse the URL to extract just the host
	// Handle both full URLs (https://example.com/path) and relative URLs (/path)
	if strings.HasPrefix(serverURL, "http://") || strings.HasPrefix(serverURL, "https://") {
		// Full URL - extract host
		parts := strings.Split(serverURL, "://")
		if len(parts) >= 2 {
			hostAndPath := parts[1]
			// Remove path if present
			hostParts := strings.Split(hostAndPath, "/")
			if len(hostParts) > 0 && hostParts[0] != "" {
				utils.DebugLog("Extracted host from OpenAPI spec servers: %s", hostParts[0])
				return hostParts[0]
			}
		}
	}

	// If it's a relative URL or couldn't parse, use default
	utils.DebugLog("Could not extract valid host from OpenAPI spec, using default: %s", defaultHost)
	return defaultHost
}

// buildTagJSON creates the tag field with metadata for differentiation
func buildTagJSON(apiName, roleArn, region, stage string) string {
	tag := map[string]string{
		"service": "aws-api-gateway",
	}

	// Only include stage if it's not empty (REST APIs have stages, HTTP APIs don't)
	if stage != "" {
		tag["stage"] = stage
	}

	tagJSON, _ := json.Marshal(tag)
	return string(tagJSON)
}

// extractRequestSchema extracts request body schema from OpenAPI operation
// Returns JSON representation of the schema or "{}" if not found
func extractRequestSchema(operation map[string]interface{}) string {
	// Check for requestBody in OpenAPI 3.0
	requestBody, ok := operation["requestBody"].(map[string]interface{})
	if !ok {
		return "{}"
	}

	// Get content types
	content, ok := requestBody["content"].(map[string]interface{})
	if !ok {
		return "{}"
	}

	// Try to find application/json content type first
	for contentType, contentObj := range content {
		if strings.Contains(strings.ToLower(contentType), "json") {
			contentMap, ok := contentObj.(map[string]interface{})
			if !ok {
				continue
			}

			// Extract schema
			schema, ok := contentMap["schema"]
			if !ok {
				continue
			}

			// Marshal schema to JSON string
			schemaJSON, err := json.Marshal(schema)
			if err != nil {
				return "{}"
			}
			return string(schemaJSON)
		}
	}

	// If no JSON content type found, try the first available
	for _, contentObj := range content {
		contentMap, ok := contentObj.(map[string]interface{})
		if !ok {
			continue
		}

		schema, ok := contentMap["schema"]
		if !ok {
			continue
		}

		schemaJSON, err := json.Marshal(schema)
		if err != nil {
			return "{}"
		}
		return string(schemaJSON)
	}

	return "{}"
}

// extractResponseSchema extracts response schema from OpenAPI operation
// Returns JSON representation of the schema or "{}" if not found
func extractResponseSchema(operation map[string]interface{}) string {
	// Check for responses in OpenAPI 3.0
	responses, ok := operation["responses"].(map[string]interface{})
	if !ok {
		return "{}"
	}

	// Try to find 200 response first, then other 2xx responses
	responseCodes := []string{"200", "201", "202", "204"}
	for _, code := range responseCodes {
		response, ok := responses[code].(map[string]interface{})
		if !ok {
			continue
		}

		// Get content types
		content, ok := response["content"].(map[string]interface{})
		if !ok {
			continue
		}

		// Try to find application/json content type first
		for contentType, contentObj := range content {
			if strings.Contains(strings.ToLower(contentType), "json") {
				contentMap, ok := contentObj.(map[string]interface{})
				if !ok {
					continue
				}

				// Extract schema
				schema, ok := contentMap["schema"]
				if !ok {
					continue
				}

				// Marshal schema to JSON string
				schemaJSON, err := json.Marshal(schema)
				if err != nil {
					return "{}"
				}
				return string(schemaJSON)
			}
		}
	}

	// If no specific response found, try the first available response with JSON content
	for _, response := range responses {
		responseMap, ok := response.(map[string]interface{})
		if !ok {
			continue
		}

		content, ok := responseMap["content"].(map[string]interface{})
		if !ok {
			continue
		}

		for _, contentObj := range content {
			contentMap, ok := contentObj.(map[string]interface{})
			if !ok {
				continue
			}

			schema, ok := contentMap["schema"]
			if !ok {
				continue
			}

			schemaJSON, err := json.Marshal(schema)
			if err != nil {
				return "{}"
			}
			return string(schemaJSON)
		}
	}

	return "{}"
}

// isHTTPMethod checks if a string is a valid HTTP method
func isHTTPMethod(s string) bool {
	method := strings.ToLower(s)
	return method == "get" || method == "post" || method == "put" ||
		method == "delete" || method == "patch" || method == "options" ||
		method == "head" || method == "trace" || method == "connect"
}
