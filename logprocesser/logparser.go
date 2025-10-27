package logprocesser

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/akto-api-security/api-gateway-logging/trafficUtil/kafkaUtil"
	"github.com/akto-api-security/api-gateway-logging/trafficUtil/utils"
)

// LogEntry holds the extracted details for a single log message.
type LogEntry struct {
	RequestID       string            `json:"request_id"`
	HTTPMethod      string            `json:"http_method"`
	ResourcePath    string            `json:"resource_path"`
	QueryParams     map[string]string `json:"query_params"`
	RequestHeaders  map[string]string `json:"request_headers"`
	RequestBody     string            `json:"request_body"`
	ResponseHeaders map[string]string `json:"response_headers"`
	ResponseBody    string            `json:"response_body"`
	StatusCode      int               `json:"status_code"`
}

var metaInfoTagsRegex = regexp.MustCompile(`(\t[^\t\n\r]+){1,2}$`)
var httpMethodRegex = regexp.MustCompile(`"httpMethod"\s*:\s*"([^"]+)"`)
var pathRegex = regexp.MustCompile(`"path"\s*:\s*"([^"]+)"`)
var statusCodeRegex = regexp.MustCompile(`"statusCode"\s*:\s*(\d+)`)

// extractMap extracts a JSON-like map from a log message.
func extractMap(log string, prefix string) map[string]string {
	utils.DebugLog("extractMap: log: , %s | prefix: %s", log, prefix)
	result := make(map[string]string)
	start := strings.Index(log, prefix)
	if start == -1 {
		return result
	}

	// Extract the raw map-like string
	raw := strings.TrimSpace(log[start+len(prefix):])
	raw = metaInfoTagsRegex.ReplaceAllString(raw, "")
	raw = strings.Trim(raw, "{}") // Remove surrounding braces

	// Split by comma to get key-value pairs
	pairs := strings.Split(raw, ", ")
	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2) // Split key and value
		if len(kv) == 2 {
			utils.DebugLog("extractMap: kv: %v", kv)
			key := strings.TrimSpace(kv[0])
			value := strings.TrimSpace(kv[1])
			result[key] = value
		}
	}

	return result
}

// extractBody extracts the body string from a log message.
func extractBody(log string, prefix string) string {
	utils.DebugLog("extractBody: log: , %s | prefix: %s", log, prefix)
	start := strings.Index(log, prefix)
	if start == -1 {
		utils.DebugLog("extractBody: index of prefix in log: , %d", start)
		return "{}"
	}

	log = log[start+len(prefix):]
	//remove last two tab-separated tokens, if present.
	log = metaInfoTagsRegex.ReplaceAllString(log, "")
	log = strings.TrimSpace(log)

	utils.DebugLog("extractBody, %s %v %s %v", log, len(log), log, start)
	if len(log) == 0 {
		return "{}"
	}
	return log
}

// DebugPrint prints the extracted log entries in JSON format for debugging.
func DebugPrint(data map[string]*LogEntry) {
	for _, entry := range data {
		output, _ := json.MarshalIndent(entry, "", "  ")
		fmt.Println(string(output))
	}
}

// extractEndpointRequestBody extracts HTTP method and path from the "Endpoint request body after transformations" JSON
func extractEndpointRequestBody(log string, logEntry *LogEntry) {
	utils.DebugLog("extractEndpointRequestBody: called with log: %s", log)
	body := extractBody(log, "Endpoint request body after transformations:")
	if body == "" || body == "{}" {
		return
	}

	// Use regex to extract httpMethod and path from partial JSON
	// works for TRUNCATED marker as well.

	// Extract httpMethod
	if logEntry.HTTPMethod == "" {
		if matches := httpMethodRegex.FindStringSubmatch(body); len(matches) > 1 {
			logEntry.HTTPMethod = matches[1]
			utils.DebugLog("extractEndpointRequestBody: extracted HTTPMethod: %s", logEntry.HTTPMethod)
		}
	}

	// Extract path
	if logEntry.ResourcePath == "" {

		if matches := pathRegex.FindStringSubmatch(body); len(matches) > 1 {
			logEntry.ResourcePath = matches[1]
			utils.DebugLog("extractEndpointRequestBody: extracted ResourcePath: %s", logEntry.ResourcePath)
		}
	}
}

// extractStatusCodeFromEndpointResponse extracts status code from endpoint response body JSON
func extractStatusCodeFromEndpointResponse(log string, logEntry *LogEntry) {
	if logEntry.StatusCode != 0 {
		return
	}

	body := extractBody(log, "Endpoint response body before transformations:")
	if body == "" || body == "{}" {
		return
	}

	// Use regex to extract statusCode from partial JSON
	// works for TRUNCATED marker as well.
	if matches := statusCodeRegex.FindStringSubmatch(body); len(matches) > 1 {
		// Parse the status code string to int
		var statusCode int
		if _, err := fmt.Sscanf(matches[1], "%d", &statusCode); err == nil {
			logEntry.StatusCode = statusCode
			utils.DebugLog("extractStatusCodeFromEndpointResponse: extracted StatusCode: %d", logEntry.StatusCode)
		}
	}
}

func ParseAndProduce(log LogEntry) {
	utils.DebugLog("ParseAndProduce: log: %+v", log)

	reqHeaderString, _ := json.Marshal(log.RequestHeaders)
	respHeaderString, _ := json.Marshal(log.ResponseHeaders)
	value := map[string]string{
		"path":            log.ResourcePath,
		"requestHeaders":  string(reqHeaderString),
		"responseHeaders": string(respHeaderString),
		"method":          log.HTTPMethod,
		"requestPayload":  log.RequestBody,
		"responsePayload": log.ResponseBody,
		"ip":              "127.0.0.1",
		// "destIp":          "",
		"time":            fmt.Sprint(time.Now().Unix()),
		"statusCode":      fmt.Sprint(log.StatusCode),
		"type":            "HTTP/1.1",
		"status":          "OK",
		"akto_account_id": fmt.Sprint(1000000),
		"akto_vxlan_id":   fmt.Sprint(0),
		"is_pending":      fmt.Sprint(false),
		"source":          "MIRRORING",
		"direction":       fmt.Sprint(1),
		"tag":             "{\n  \"service\": \"aws-api-gateway\"\n}",
	}

	utils.DebugLog("ParseAndProduce: value: %+v", value)

	kafkaUtil.ParseAndProduce(value)
}
