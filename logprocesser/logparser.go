package logprocesser

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/akto-api-security/api-gateway-logging/accountconfig"
	"github.com/akto-api-security/api-gateway-logging/loggroupdiscovery"
	"github.com/akto-api-security/api-gateway-logging/trafficUtil/kafkaUtil"
	"github.com/akto-api-security/api-gateway-logging/trafficUtil/utils"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/yinxulai/go-jsonrepair/jsonrepair"
)

// LogEntry holds the extracted details for a single log message.
type LogEntry struct {
	RequestID             string            `json:"request_id"`
	HTTPMethod            string            `json:"http_method"`
	ResourcePath          string            `json:"resource_path"`
	QueryParams           map[string]string `json:"query_params"`
	RequestHeaders        map[string]string `json:"request_headers"`
	RequestBody           string            `json:"request_body"`
	ResponseHeaders       map[string]string `json:"response_headers"`
	ResponseBody          string            `json:"response_body"`
	StatusCode            int               `json:"status_code"`
	RequestBodyTruncated  bool              `json:"request_body_truncated"`
	ResponseBodyTruncated bool              `json:"response_body_truncated"`
	LogGroupIdentifier    string            `json:"log_group_identifier"`
	AwsAccountId          string            `json:"aws_account_id"`
}

// HostFromLogGroupIdentifier derives a host value from a log group ARN or name.
// For ARN format (e.g. arn:aws:logs:eu-west-1:524348298903:log-group:API-Gateway-Execution-Logs_c1xxzmg784/Prod),
// the log group name is the segment after ":log-group:". In all cases, "/" in the derived string
// is replaced with ".": primary convention uses the part after "API-Gateway-Execution-Logs_";
// fallback uses the full log group name.
func HostFromLogGroupIdentifier(identifier string) string {
	if identifier == "" {
		return ""
	}
	name := identifier
	if idx := strings.Index(identifier, ":log-group:"); idx != -1 {
		name = strings.TrimSpace(identifier[idx+len(":log-group:"):])
	}
	if name == "" {
		return ""
	}
	base := name
	if strings.HasPrefix(name, loggroupdiscovery.ApiGatewayExecutionLogGroupPrefix) {
		base = name[len(loggroupdiscovery.ApiGatewayExecutionLogGroupPrefix):]
	}
	base = strings.TrimLeft(base, "/")
	return strings.ReplaceAll(base, "/", ".")
}

// extractMap extracts a JSON-like map from a log message.
func extractMap(log string, prefix string) map[string]string {
	result := make(map[string]string)
	start := strings.Index(log, prefix)
	if start == -1 {
		return result
	}

	// Extract the raw map-like string
	raw := strings.TrimSpace(log[start+len(prefix):])
	raw = strings.Trim(raw, "{}") // Remove surrounding braces

	// Split by comma to get key-value pairs
	pairs := strings.Split(raw, ", ")
	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2) // Split key and value
		if len(kv) == 2 {
			key := strings.TrimSpace(kv[0])
			value := strings.TrimSpace(kv[1])
			result[key] = value
		}
	}

	return result
}

// extractBody extracts the body string from a log message.
func extractBody(log string, prefix string) string {
	start := strings.Index(log, prefix)
	if start == -1 {
		return "{}"
	}
	// fmt.Printf("extractBody, %s %v %s %v\n", log, len(strings.TrimSpace(log[start+len(prefix):])), strings.TrimSpace(log[start+len(prefix):]), start)
	if len(strings.TrimSpace(log[start+len(prefix):])) == 0 {
		return "{}"
	}
	return strings.TrimSpace(log[start+len(prefix):])
}

// RepairTruncatedJSON attempts to repair truncated JSON by completing the structure.
// Returns the repaired JSON string and a boolean indicating if it was truncated.
func RepairTruncatedJSON(body string) (string, bool) {
	if body == "" || body == "{}" {
		return body, false
	}

	// Check if body is truncated (ends with [TRUNCATED])
	hasTruncMarker := strings.HasSuffix(body, "[TRUNCATED]")

	// If no truncation marker, return as-is (don't modify non-truncated bodies)
	if !hasTruncMarker {
		return body, false
	}

	// Remove [TRUNCATED] marker
	cleanBody := strings.TrimSuffix(body, "[TRUNCATED]")
	cleanBody = strings.TrimSpace(cleanBody)

	if cleanBody == "" {
		return "{}", true
	}

	// Repair the JSON using the library
	repaired, err := jsonrepair.Repair(cleanBody)
	if err != nil {
		utils.LogToCyborg("error", "RepairTruncatedJSON: repair failed for truncated body")
		// If repair fails, return cleaned body
		return cleanBody, true
	}

	// Post-process: fix incomplete key-value pairs (key without colon/value)
	repaired = fixIncompleteKeyValuePairs(repaired)

	// Final validation - if still invalid, return cleaned body
	if !json.Valid([]byte(repaired)) {
		utils.LogToCyborg("error", "RepairTruncatedJSON: repaired JSON still invalid. Returning original body.")
		return cleanBody, true
	}

	log.Printf("RepairTruncatedJSON: successfully repaired truncated JSON (original len=%d)", len(cleanBody))
	return repaired, true
}

// fixIncompleteKeyValuePairs removes keys that have no value from JSON.
// Pattern: ,"key"} or ,"key"] - the incomplete key is removed entirely.
func fixIncompleteKeyValuePairs(jsonStr string) string {
	// Remove pattern: ,"key"} -> }
	re1 := regexp.MustCompile(`,"[^"]*"\}`)
	result := re1.ReplaceAllString(jsonStr, "}")

	// Remove pattern: ,"key"] -> ]
	re2 := regexp.MustCompile(`,"[^"]*"\]`)
	result = re2.ReplaceAllString(result, "]")

	// Remove pattern: {"key"} -> {} (first key in object)
	re3 := regexp.MustCompile(`\{"[^"]*"\}`)
	result = re3.ReplaceAllString(result, "{}")

	return result
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ProcessEventsIntoLogEntries is the original event-reading logic (unchanged). It processes
// events into logEntries by requestID and returns the max event timestamp in the batch.
func ProcessEventsIntoLogEntries(events []types.OutputLogEvent, logGroupName, streamName string, logEntries map[string]*LogEntry) (maxTimestamp int64) {
	reqIDRegex := regexp.MustCompile(`\(([^)]+)\)`)
	httpMethodRegex := regexp.MustCompile(`HTTP Method:\s*(\S+),\s*Resource Path:\s*(\S+)`)
	eventsWithReqID := 0
	eventsWithoutReqID := 0

	for _, event := range events {
		if event.Message == nil {
			continue
		}
		message := *event.Message
		if event.Timestamp != nil && *event.Timestamp > maxTimestamp {
			maxTimestamp = *event.Timestamp
		}

		ts := "n/a"
		if event.Timestamp != nil {
			ts = fmt.Sprintf("%d", *event.Timestamp)
		}
		utils.LogToCyborg("info", fmt.Sprintf("Event Data: %s | %s | %s", streamName, ts, message))

		var logEntry map[string]interface{}
		isJSON := false
		err := json.Unmarshal([]byte(message), &logEntry)

		var reqID string

		if err == nil {
			isJSON = true
			if reqIDVal, exists := logEntry["requestId"]; exists {
				if reqIDStr, ok := reqIDVal.(string); ok {
					reqID = reqIDStr
					log.Printf("DEBUG [%s] Parsed JSON format - requestId: %s", streamName, reqID)
				}
			} else if extReqIDVal, exists := logEntry["extendedRequestId"]; exists {
				if extReqIDStr, ok := extReqIDVal.(string); ok {
					reqID = extReqIDStr
					log.Printf("DEBUG [%s] Parsed JSON format - extendedRequestId: %s", streamName, reqID)
				}
			}
		} else {
			isJSON = false
			matches := reqIDRegex.FindStringSubmatch(message)
			if len(matches) >= 2 {
				reqID = matches[1]
			}
		}

		if reqID == "" {
			eventsWithoutReqID++
			if eventsWithoutReqID <= 3 {
				log.Printf("DEBUG [%s] Could not parse request ID (sample %d): %s", streamName, eventsWithoutReqID, message[:minInt(200, len(message))])
			}
			continue
		}
		eventsWithReqID++

		if _, exists := logEntries[reqID]; !exists {
			logEntries[reqID] = &LogEntry{
				RequestID:          reqID,
				QueryParams:        make(map[string]string),
				RequestHeaders:     make(map[string]string),
				ResponseHeaders:    make(map[string]string),
				LogGroupIdentifier: logGroupName,
				AwsAccountId:       accountconfig.ExtractAwsAccountIdFromLogGroupArn(logGroupName),
			}
		}

		entry := logEntries[reqID]

		if isJSON && err == nil {
			if httpMethod, exists := logEntry["httpMethod"]; exists {
				if httpMethodStr, ok := httpMethod.(string); ok {
					entry.HTTPMethod = httpMethodStr
				}
			} else if method, exists := logEntry["method"]; exists {
				if methodStr, ok := method.(string); ok {
					entry.HTTPMethod = methodStr
				}
			}

			if resourcePath, exists := logEntry["resourcePath"]; exists {
				if resourcePathStr, ok := resourcePath.(string); ok {
					entry.ResourcePath = resourcePathStr
				}
			} else if path, exists := logEntry["path"]; exists {
				if pathStr, ok := path.(string); ok {
					entry.ResourcePath = pathStr
				}
			}

			if status, exists := logEntry["status"]; exists {
				switch v := status.(type) {
				case float64:
					entry.StatusCode = int(v)
				case string:
					if code, err := strconv.Atoi(v); err == nil {
						entry.StatusCode = code
					}
				}
			} else if statusCode, exists := logEntry["statusCode"]; exists {
				switch v := statusCode.(type) {
				case float64:
					entry.StatusCode = int(v)
				case string:
					if code, err := strconv.Atoi(v); err == nil {
						entry.StatusCode = code
					}
				}
			}

			if headers, exists := logEntry["headers"]; exists {
				if headersMap, ok := headers.(map[string]interface{}); ok {
					for k, v := range headersMap {
						if vStr, ok := v.(string); ok {
							entry.RequestHeaders[k] = vStr
						}
					}
				}
			}

			if responseHeaders, exists := logEntry["responseHeaders"]; exists {
				if headersMap, ok := responseHeaders.(map[string]interface{}); ok {
					for k, v := range headersMap {
						if vStr, ok := v.(string); ok {
							entry.ResponseHeaders[k] = vStr
						}
					}
				}
			}

			if requestPayload, exists := logEntry["requestPayload"]; exists {
				if payloadStr, ok := requestPayload.(string); ok {
					repairedBody, wasTruncated := RepairTruncatedJSON(payloadStr)
					entry.RequestBody = repairedBody
					if wasTruncated {
						entry.RequestBodyTruncated = true
					}
				}
			}

			if responsePayload, exists := logEntry["responsePayload"]; exists {
				if payloadStr, ok := responsePayload.(string); ok {
					repairedBody, wasTruncated := RepairTruncatedJSON(payloadStr)
					entry.ResponseBody = repairedBody
					if wasTruncated {
						entry.ResponseBodyTruncated = true
					}
				}
			}

			if entry.HTTPMethod != "" {
				log.Printf("DEBUG [%s] Extracted from JSON: %s %s (status: %d)", streamName, entry.HTTPMethod, entry.ResourcePath, entry.StatusCode)
				if len(entry.RequestHeaders) > 0 {
					log.Printf("DEBUG [%s]   RequestHeaders: %v", streamName, entry.RequestHeaders)
				}
				if len(entry.ResponseHeaders) > 0 {
					log.Printf("DEBUG [%s]   ResponseHeaders: %v", streamName, entry.ResponseHeaders)
				}
				if entry.RequestBody != "" {
					log.Printf("DEBUG [%s]   RequestBody: %s", streamName, entry.RequestBody[:minInt(100, len(entry.RequestBody))])
				}
				if entry.ResponseBody != "" {
					log.Printf("DEBUG [%s]   ResponseBody: %s", streamName, entry.ResponseBody[:minInt(100, len(entry.ResponseBody))])
				}
			}
		} else {
			if strings.Contains(message, "HTTP Method:") && strings.Contains(message, "Resource Path:") {
				matches := httpMethodRegex.FindStringSubmatch(message)
				if len(matches) == 3 {
					entry.HTTPMethod = matches[1]
					entry.ResourcePath = matches[2]
				} else {
					utils.LogToCyborg("error", "Could not extract HTTP Method and Resource Path from log message")
				}
			} else if strings.Contains(message, "Method request query string:") {
				entry.QueryParams = extractMap(message, "Method request query string:")
			} else if strings.Contains(message, "Method request headers:") {
				entry.RequestHeaders = extractMap(message, "Method request headers:")
			} else if strings.Contains(message, "Method request body before transformations:") {
				rawBody := extractBody(message, "Method request body before transformations:")
				repairedBody, wasTruncated := RepairTruncatedJSON(rawBody)
				entry.RequestBody = repairedBody
				entry.RequestBodyTruncated = wasTruncated
			} else if strings.Contains(message, "Method response headers:") {
				entry.ResponseHeaders = extractMap(message, "Method response headers:")
			} else if strings.Contains(message, "Method response body after transformations:") {
				rawBody := extractBody(message, "Method response body after transformations:")
				repairedBody, wasTruncated := RepairTruncatedJSON(rawBody)
				entry.ResponseBody = repairedBody
				entry.ResponseBodyTruncated = wasTruncated
			} else if strings.Contains(message, "Method completed with status:") {
				parts := strings.Split(message, "Method completed with status:")
				if len(parts) > 1 {
					statusCodeStr := strings.TrimSpace(parts[1])
					statusCode, err := strconv.Atoi(statusCodeStr)
					if err == nil {
						entry.StatusCode = statusCode
					} else {
						utils.LogToCyborg("error", "Error converting status code to integer: "+err.Error())
					}
				} else {
					utils.LogToCyborg("error", "Could not find status code in the message")
				}
			}
		}
	}

	log.Printf("DEBUG [%s] Summary: %d events with request IDs, %d without", streamName, eventsWithReqID, eventsWithoutReqID)
	return maxTimestamp
}

// DebugPrint prints the extracted log entries in JSON format for debugging.
func DebugPrint(data map[string]*LogEntry) {
	for _, entry := range data {
		output, _ := json.MarshalIndent(entry, "", "  ")
		log.Println(string(output))
	}
}

// hasHostHeader returns true if headers contain a host key (case-insensitive).
func hasHostHeader(headers map[string]string) bool {
	for k := range headers {
		if strings.EqualFold(k, "host") {
			return true
		}
	}
	return false
}

func normalizePathTrailingSlash(p string) string {
	if p == "" {
		return p
	}
	if trimmed := strings.TrimRight(p, "/"); trimmed != "" {
		return trimmed
	}
	return "/"
}

func ParseAndProduce(entry LogEntry) {
	entry.ResourcePath = normalizePathTrailingSlash(entry.ResourcePath)
	utils.LogToCyborg("info", "Processing traffic: "+entry.HTTPMethod+" "+entry.ResourcePath+" (status: "+fmt.Sprint(entry.StatusCode)+")")
	// Initialize header maps if nil to avoid nil map assignment panic
	if entry.RequestHeaders == nil {
		entry.RequestHeaders = make(map[string]string)
	}
	if entry.ResponseHeaders == nil {
		entry.ResponseHeaders = make(map[string]string)
	}

	// Backfill Host header from log group if missing
	if !hasHostHeader(entry.RequestHeaders) {
		if host := HostFromLogGroupIdentifier(entry.LogGroupIdentifier); host != "" {
			entry.RequestHeaders["Host"] = host
		}
	}

	// Add truncation headers
	if entry.RequestBodyTruncated {
		entry.RequestHeaders["x-akto-payload-truncated"] = "true"
	}
	if entry.ResponseBodyTruncated {
		entry.ResponseHeaders["x-akto-payload-truncated"] = "true"
	}

	// Look up Akto account ID from AWS account ID
	aktoAccountId := accountconfig.GetAktoAccountId(entry.AwsAccountId)

	reqHeaderString, _ := json.Marshal(entry.RequestHeaders)
	respHeaderString, _ := json.Marshal(entry.ResponseHeaders)
	trafficData := map[string]string{
		"path":            entry.ResourcePath,
		"requestHeaders":  string(reqHeaderString),
		"responseHeaders": string(respHeaderString),
		"method":          entry.HTTPMethod,
		"requestPayload":  entry.RequestBody,
		"responsePayload": entry.ResponseBody,
		"ip":              "127.0.0.1",
		// "destIp":          "",
		"time":            fmt.Sprint(time.Now().Unix()),
		"statusCode":      fmt.Sprint(entry.StatusCode),
		"type":            "HTTP/1.1",
		"status":          "OK",
		"akto_account_id": fmt.Sprint(aktoAccountId),
		"akto_vxlan_id":   fmt.Sprint(0),
		"is_pending":      fmt.Sprint(false),
		"source":          "MIRRORING",
		"direction":       fmt.Sprint(1),
		"tag":             "{\n  \"service\": \"aws-api-gateway\"\n}",
	}

	// Debug: Print the Kafka message being sent
	msgBytes, _ := json.MarshalIndent(trafficData, "", "  ")
	log.Printf("KAFKA MESSAGE BEING SENT:\n%s\n", string(msgBytes))

	kafkaUtil.ParseAndProduce(trafficData)
}
