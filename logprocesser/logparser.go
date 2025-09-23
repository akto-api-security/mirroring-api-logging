package logprocesser

import (
	"encoding/json"
	"fmt"
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
	utils.DebugLog("extractBody, %s %v %s %v", log, len(strings.TrimSpace(log[start+len(prefix):])), strings.TrimSpace(log[start+len(prefix):]), start)
	if len(strings.TrimSpace(log[start+len(prefix):])) == 0 {
		return "{}"
	}
	return strings.TrimSpace(log[start+len(prefix):])
}

// DebugPrint prints the extracted log entries in JSON format for debugging.
func DebugPrint(data map[string]*LogEntry) {
	for _, entry := range data {
		output, _ := json.MarshalIndent(entry, "", "  ")
		fmt.Println(string(output))
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
