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
	roleArn string,
	region string,
	stage string,
) error {
	// Parse OpenAPI JSON
	var spec map[string]interface{}
	if err := json.Unmarshal(specContent, &spec); err != nil {
		return fmt.Errorf("failed to parse OpenAPI spec: %v", err)
	}

	// Extract paths from OpenAPI spec
	paths, ok := spec["paths"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("no paths found in OpenAPI spec")
	}

	endpointCount := 0

	// For each path and method, create a Kafka message
	for path, pathItem := range paths {
		pathObj, ok := pathItem.(map[string]interface{})
		if !ok {
			continue
		}

		// Iterate methods (get, post, put, delete, etc.)
		for method, operation := range pathObj {
			if !isHTTPMethod(method) {
				continue // Skip non-method fields like "parameters", "servers", etc.
			}

			operationObj, ok := operation.(map[string]interface{})
			if !ok {
				continue
			}

			// Extract request and response schemas
			requestSchema := extractRequestSchema(operationObj)
			responseSchema := extractResponseSchema(operationObj)

			// Create message in existing traffic log format
			value := map[string]string{
				"path":            path,
				"method":          strings.ToUpper(method),
				"requestHeaders":  "{}",           // Empty for spec-based discovery
				"responseHeaders": "{}",           // Empty for spec-based discovery
				"requestPayload":  requestSchema,  // JSON schema from OpenAPI
				"responsePayload": responseSchema, // JSON schema from OpenAPI
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

			// Send to Kafka using existing utility
			kafkaUtil.ParseAndProduce(value)
			endpointCount++
		}
	}

	utils.DebugLog("Sent %d endpoints from API %s to Kafka", endpointCount, apiName)
	return nil
}

// buildTagJSON creates the tag field with metadata for differentiation
// Key field: "type": "openapi-discovery" to distinguish from traffic logs
func buildTagJSON(apiName, roleArn, region, stage string) string {
	tag := map[string]string{
		"service":  "aws-api-gateway",
		"type":     "openapi-discovery", // DIFFERENTIATION KEY
		"api_name": apiName,
		"role_arn": roleArn,
		"region":   region,
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
