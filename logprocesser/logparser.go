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

var metaInfoTagsRegex = regexp.MustCompile(`(\t[^\t\n\r]+){1,2}$`)
var httpMethodBodyRegex = regexp.MustCompile(`"httpMethod"\s*:\s*"([^"]+)"`)
var pathBodyRegex = regexp.MustCompile(`"path"\s*:\s*"([^"]+)"`)
var statusCodeBodyRegex = regexp.MustCompile(`"statusCode"\s*:\s*(\d+)`)

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

// extractMap extracts a JSON-like map from a log message.
func extractMap(log string, prefix string) map[string]string {
	result := make(map[string]string)
	start := strings.Index(log, prefix)
	if start == -1 {
		return result
	}

	raw := strings.TrimSpace(log[start+len(prefix):])
	raw = metaInfoTagsRegex.ReplaceAllString(raw, "")
	raw = strings.Trim(raw, "{}")

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

	body := log[start+len(prefix):]
	body = metaInfoTagsRegex.ReplaceAllString(body, "")
	body = strings.TrimSpace(body)

	if len(body) == 0 {
		return "{}"
	}
	return body
}

// DebugPrint prints the extracted log entries in JSON format for debugging.
func DebugPrint(data map[string]*LogEntry) {
	for _, entry := range data {
		output, _ := json.MarshalIndent(entry, "", "  ")
		fmt.Println(string(output))
	}
}

func extractEndpointRequestBody(log string, logEntry *LogEntry) {
	body := extractBody(log, "Endpoint request body after transformations:")
	if body == "" || body == "{}" {
		return
	}

	if logEntry.HTTPMethod == "" {
		if matches := httpMethodBodyRegex.FindStringSubmatch(body); len(matches) > 1 {
			logEntry.HTTPMethod = matches[1]
			utils.DebugLog("extractEndpointRequestBody: extracted HTTPMethod: %s", logEntry.HTTPMethod)
		}
	}

	if logEntry.ResourcePath == "" {
		if matches := pathBodyRegex.FindStringSubmatch(body); len(matches) > 1 {
			logEntry.ResourcePath = matches[1]
			utils.DebugLog("extractEndpointRequestBody: extracted ResourcePath: %s", logEntry.ResourcePath)
		}
	}
}

func extractStatusCodeFromEndpointResponse(log string, logEntry *LogEntry) {
	if logEntry.StatusCode != 0 {
		return
	}

	body := extractBody(log, "Endpoint response body before transformations:")
	if body == "" || body == "{}" {
		return
	}

	if matches := statusCodeBodyRegex.FindStringSubmatch(body); len(matches) > 1 {
		var statusCode int
		if _, err := fmt.Sscanf(matches[1], "%d", &statusCode); err == nil {
			logEntry.StatusCode = statusCode
			utils.DebugLog("extractStatusCodeFromEndpointResponse: extracted StatusCode: %d", logEntry.StatusCode)
		}
	}
}

func ParseAndProduce(log LogEntry) {

	reqHeaderString, _ := json.Marshal(log.RequestHeaders)
	respHeaderString, _ := json.Marshal(log.ResponseHeaders)
	trafficData := map[string]string{
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

	// Debug: Print the Kafka message being sent
	msgBytes, _ := json.MarshalIndent(trafficData, "", "  ")
	fmt.Printf("KAFKA MESSAGE BEING SENT:\n%s\n", string(msgBytes))

	kafkaUtil.ParseAndProduce(trafficData)
}
