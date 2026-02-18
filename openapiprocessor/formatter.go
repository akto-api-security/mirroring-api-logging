package openapiprocessor

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/akto-api-security/api-gateway-logging/trafficUtil/kafkaUtil"
	"github.com/akto-api-security/api-gateway-logging/trafficUtil/utils"
	"github.com/getkin/kin-openapi/openapi3"
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

	// Parse OpenAPI spec with kin-openapi (auto-resolves all $ref references)
	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true

	doc, err := loader.LoadFromData(specContent)
	if err != nil {
		utils.DebugLog("ERROR: Failed to parse OpenAPI spec for %s: %v", apiName, err)
		return fmt.Errorf("failed to parse OpenAPI spec: %v", err)
	}

	// Validate and resolve all references
	if err := doc.Validate(loader.Context); err != nil {
		utils.DebugLog("WARNING: OpenAPI spec validation failed for %s: %v", apiName, err)
		// Continue anyway - partial data is better than none
	}

	paths := doc.Paths
	if paths == nil || len(paths.Map()) == 0 {
		utils.DebugLog("WARNING: No paths found in OpenAPI spec for %s", apiName)
		return fmt.Errorf("no paths found in OpenAPI spec")
	}

	utils.DebugLog("Found %d paths in OpenAPI spec for %s", len(paths.Map()), apiName)

	// Extract host from OpenAPI spec servers or construct from API ID
	defaultHost := extractHostFromSpec(doc, apiId, region)
	utils.DebugLog("Using host: %s for API %s", defaultHost, apiName)

	endpointCount := 0
	successCount := 0
	failedCount := 0
	loggedSample := false

	// For each path and method, create a Kafka message
	for path, pathItem := range paths.Map() {
		if pathItem == nil {
			utils.DebugLog("WARNING: Skipping nil path item for %s", path)
			continue
		}

		// Iterate through HTTP methods
		for method, operation := range pathItem.Operations() {
			if operation == nil {
				continue
			}

			// Extract request and response payloads (with $ref resolution!)
			requestPayload := extractRequestPayload(operation)
			responsePayload := extractResponsePayload(operation)

			// Extract request and response headers with examples
			requestHeadersJSON := extractRequestHeaders(operation, defaultHost)
			responseHeadersJSON := extractResponseHeaders(operation)

			// Create message in existing traffic log format
			value := map[string]string{
				"path":            path,
				"method":          strings.ToUpper(method),
				"requestHeaders":  requestHeadersJSON,  // Headers with examples from spec
				"responseHeaders": responseHeadersJSON, // Headers with examples from spec
				"requestPayload":  requestPayload,      // Sample payload from OpenAPI (resolved $refs)
				"responsePayload": responsePayload,     // Sample payload from OpenAPI (resolved $refs)
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
func extractHostFromSpec(doc *openapi3.T, apiId string, region string) string {
	// Default fallback: construct from API ID and region
	defaultHost := fmt.Sprintf("%s.execute-api.%s.amazonaws.com", apiId, region)

	// Try to extract from servers array
	if doc.Servers == nil || len(doc.Servers) == 0 {
		return defaultHost
	}

	// Get the first server URL
	firstServer := doc.Servers[0]
	serverURL := firstServer.URL
	if serverURL == "" {
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

// extractRequestPayload extracts a sample request body from OpenAPI operation
// Priority: 1) Examples from spec, 2) Generate from schema, 3) Empty object
// Returns JSON string representation
func extractRequestPayload(operation *openapi3.Operation) string {
	if operation.RequestBody == nil || operation.RequestBody.Value == nil {
		return "{}"
	}

	requestBody := operation.RequestBody.Value

	// Try to find application/json content type
	jsonContent := requestBody.Content.Get("application/json")
	if jsonContent == nil {
		// Try any content type that contains "json"
		for contentType, content := range requestBody.Content {
			if strings.Contains(strings.ToLower(contentType), "json") {
				jsonContent = content
				break
			}
		}
	}

	if jsonContent == nil || jsonContent.Schema == nil || jsonContent.Schema.Value == nil {
		return "{}"
	}

	// Priority 1: Check for examples in the content
	if jsonContent.Example != nil {
		exampleJSON, err := json.Marshal(jsonContent.Example)
		if err == nil {
			return string(exampleJSON)
		}
	}

	// Priority 2: Check for examples in the schema
	if jsonContent.Schema.Value.Example != nil {
		exampleJSON, err := json.Marshal(jsonContent.Schema.Value.Example)
		if err == nil {
			return string(exampleJSON)
		}
	}

	// Priority 3: Generate sample from schema (all $refs already resolved by kin-openapi!)
	schema := jsonContent.Schema.Value
	sample := generateSampleFromSchema(schema, make(map[*openapi3.Schema]bool))

	sampleJSON, err := json.Marshal(sample)
	if err != nil {
		return "{}"
	}

	return string(sampleJSON)
}

// extractResponsePayload extracts a sample response body from OpenAPI operation
// Priority: 1) Examples from spec, 2) Generate from schema, 3) Empty object
// Returns JSON string representation
func extractResponsePayload(operation *openapi3.Operation) string {
	if operation.Responses == nil {
		return "{}"
	}

	// Try common success response codes in order
	responseCodes := []string{"200", "201", "202", "204"}
	var jsonContent *openapi3.MediaType

	for _, code := range responseCodes {
		response := operation.Responses.Value(code)
		if response == nil || response.Value == nil {
			continue
		}

		// Try to find application/json content type
		jsonContent = response.Value.Content.Get("application/json")
		if jsonContent == nil {
			// Try any content type that contains "json"
			for contentType, content := range response.Value.Content {
				if strings.Contains(strings.ToLower(contentType), "json") {
					jsonContent = content
					break
				}
			}
		}

		if jsonContent != nil {
			break
		}
	}

	// If no success response found, try the first available response
	if jsonContent == nil {
		for _, response := range operation.Responses.Map() {
			if response == nil || response.Value == nil {
				continue
			}

			jsonContent = response.Value.Content.Get("application/json")
			if jsonContent == nil {
				for contentType, content := range response.Value.Content {
					if strings.Contains(strings.ToLower(contentType), "json") {
						jsonContent = content
						break
					}
				}
			}

			if jsonContent != nil {
				break
			}
		}
	}

	if jsonContent == nil || jsonContent.Schema == nil || jsonContent.Schema.Value == nil {
		return "{}"
	}

	// Priority 1: Check for examples in the content
	if jsonContent.Example != nil {
		exampleJSON, err := json.Marshal(jsonContent.Example)
		if err == nil {
			return string(exampleJSON)
		}
	}

	// Priority 2: Check for examples in the schema
	if jsonContent.Schema.Value.Example != nil {
		exampleJSON, err := json.Marshal(jsonContent.Schema.Value.Example)
		if err == nil {
			return string(exampleJSON)
		}
	}

	// Priority 3: Generate sample from schema (all $refs already resolved!)
	schema := jsonContent.Schema.Value
	sample := generateSampleFromSchema(schema, make(map[*openapi3.Schema]bool))

	sampleJSON, err := json.Marshal(sample)
	if err != nil {
		return "{}"
	}

	return string(sampleJSON)
}

// extractRequestHeaders extracts request headers from OpenAPI operation with examples
// Returns JSON string representation of headers
func extractRequestHeaders(operation *openapi3.Operation, defaultHost string) string {
	headers := map[string]string{
		"host": defaultHost, // Always include host
	}

	// Extract headers from parameters
	for _, paramRef := range operation.Parameters {
		if paramRef == nil || paramRef.Value == nil {
			continue
		}

		param := paramRef.Value
		if param.In != "header" {
			continue
		}

		// Get header name
		headerName := param.Name
		var headerValue string

		// Priority 1: Use example if available
		if param.Example != nil {
			headerValue = fmt.Sprint(param.Example)
		} else if param.Schema != nil && param.Schema.Value != nil {
			// Priority 2: Use schema example
			if param.Schema.Value.Example != nil {
				headerValue = fmt.Sprint(param.Schema.Value.Example)
			} else {
				// Priority 3: Generate sample from schema
				sample := generateSampleFromSchema(param.Schema.Value, make(map[*openapi3.Schema]bool))
				headerValue = fmt.Sprint(sample)
			}
		}

		if headerValue != "" {
			headers[headerName] = headerValue
		}
	}

	headersJSON, _ := json.Marshal(headers)
	return string(headersJSON)
}

// extractResponseHeaders extracts response headers from OpenAPI operation with examples
// Returns JSON string representation of headers
func extractResponseHeaders(operation *openapi3.Operation) string {
	if operation.Responses == nil {
		return "{}"
	}

	// Try common success response codes
	responseCodes := []string{"200", "201", "202", "204"}

	for _, code := range responseCodes {
		response := operation.Responses.Value(code)
		if response == nil || response.Value == nil {
			continue
		}

		if response.Value.Headers == nil || len(response.Value.Headers) == 0 {
			continue
		}

		headers := make(map[string]string)

		// Extract each header
		for headerName, headerRef := range response.Value.Headers {
			if headerRef == nil || headerRef.Value == nil {
				continue
			}

			header := headerRef.Value
			var headerValue string

			// Priority 1: Use example if available
			if header.Example != nil {
				headerValue = fmt.Sprint(header.Example)
			} else if header.Schema != nil && header.Schema.Value != nil {
				// Priority 2: Use schema example
				if header.Schema.Value.Example != nil {
					headerValue = fmt.Sprint(header.Schema.Value.Example)
				} else {
					// Priority 3: Generate sample from schema
					sample := generateSampleFromSchema(header.Schema.Value, make(map[*openapi3.Schema]bool))
					headerValue = fmt.Sprint(sample)
				}
			}

			if headerValue != "" {
				headers[headerName] = headerValue
			}
		}

		if len(headers) > 0 {
			headersJSON, _ := json.Marshal(headers)
			return string(headersJSON)
		}
	}

	return "{}"
}

// generateSampleFromSchema creates a sample JSON object from an OpenAPI schema
// The schema has all $ref references already resolved by kin-openapi
// Uses a visited map to prevent infinite recursion on circular references
func generateSampleFromSchema(schema *openapi3.Schema, visited map[*openapi3.Schema]bool) interface{} {
	if schema == nil {
		return nil
	}

	// Prevent circular reference infinite loops
	if visited[schema] {
		return nil
	}
	visited[schema] = true
	defer func() { delete(visited, schema) }()

	// If schema has an example, use it
	if schema.Example != nil {
		return schema.Example
	}

	// Get the type - it's a slice in newer kin-openapi versions
	var schemaType string
	if schema.Type != nil && len(*schema.Type) > 0 {
		schemaType = (*schema.Type)[0]
	}

	// Handle oneOf / anyOf first (before type checking)
	if len(schema.OneOf) > 0 && schema.OneOf[0] != nil && schema.OneOf[0].Value != nil {
		return generateSampleFromSchema(schema.OneOf[0].Value, visited)
	}
	if len(schema.AnyOf) > 0 && schema.AnyOf[0] != nil && schema.AnyOf[0].Value != nil {
		return generateSampleFromSchema(schema.AnyOf[0].Value, visited)
	}

	// Handle different schema types
	switch schemaType {
	case "object", "":
		// Generate object with properties
		result := make(map[string]interface{})

		for propName, propSchemaRef := range schema.Properties {
			if propSchemaRef == nil || propSchemaRef.Value == nil {
				continue
			}
			result[propName] = generateSampleFromSchema(propSchemaRef.Value, visited)
		}

		// Handle allOf (merge all schemas)
		for _, schemaRef := range schema.AllOf {
			if schemaRef == nil || schemaRef.Value == nil {
				continue
			}
			subResult := generateSampleFromSchema(schemaRef.Value, visited)
			if subObj, ok := subResult.(map[string]interface{}); ok {
				for k, v := range subObj {
					result[k] = v
				}
			}
		}

		return result

	case "array":
		// Generate array with one sample item
		if schema.Items == nil || schema.Items.Value == nil {
			return []interface{}{}
		}

		sample := generateSampleFromSchema(schema.Items.Value, visited)
		return []interface{}{sample}

	case "string":
		// Use format for more realistic samples
		switch schema.Format {
		case "date":
			return "2024-01-01"
		case "date-time":
			return "2024-01-01T00:00:00Z"
		case "email":
			return "user@example.com"
		case "uuid":
			return "123e4567-e89b-12d3-a456-426614174000"
		case "uri", "url":
			return "https://example.com"
		default:
			// Use enum if available
			if len(schema.Enum) > 0 {
				return schema.Enum[0]
			}
			return "string"
		}

	case "integer":
		if len(schema.Enum) > 0 {
			return schema.Enum[0]
		}
		return 0

	case "number":
		if len(schema.Enum) > 0 {
			return schema.Enum[0]
		}
		return 0.0

	case "boolean":
		return false

	default:
		// If no type specified but has properties, treat as object
		if len(schema.Properties) > 0 {
			result := make(map[string]interface{})
			for propName, propSchemaRef := range schema.Properties {
				if propSchemaRef == nil || propSchemaRef.Value == nil {
					continue
				}
				result[propName] = generateSampleFromSchema(propSchemaRef.Value, visited)
			}
			return result
		}
		return nil
	}
}

// isHTTPMethod checks if a string is a valid HTTP method
func isHTTPMethod(s string) bool {
	method := strings.ToLower(s)
	return method == "get" || method == "post" || method == "put" ||
		method == "delete" || method == "patch" || method == "options" ||
		method == "head" || method == "trace" || method == "connect"
}
