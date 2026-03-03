package logprocesser

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/akto-api-security/api-gateway-logging/trafficUtil/kafkaUtil"
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
		log.Printf("RepairTruncatedJSON: repair failed for truncated body (len=%d): %v", len(cleanBody), err)
		// If repair fails, return cleaned body
		return cleanBody, true
	}

	// Post-process: fix incomplete key-value pairs (key without colon/value)
	repaired = fixIncompleteKeyValuePairs(repaired)

	// Final validation - if still invalid, return cleaned body
	if !json.Valid([]byte(repaired)) {
		log.Printf("RepairTruncatedJSON: repaired JSON still invalid (body len=%d)", len(cleanBody))
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

// DebugPrint prints the extracted log entries in JSON format for debugging.
func DebugPrint(data map[string]*LogEntry) {
	for _, entry := range data {
		output, _ := json.MarshalIndent(entry, "", "  ")
		log.Println(string(output))
	}
}

func ParseAndProduce(entry LogEntry) {
	log.Printf("ParseAndProduce: request_id=%s method=%s path=%s status=%d", entry.RequestID, entry.HTTPMethod, entry.ResourcePath, entry.StatusCode)
	// Initialize header maps if nil to avoid nil map assignment panic
	if entry.RequestHeaders == nil {
		entry.RequestHeaders = make(map[string]string)
	}
	if entry.ResponseHeaders == nil {
		entry.ResponseHeaders = make(map[string]string)
	}

	// Add truncation headers
	if entry.RequestBodyTruncated {
		entry.RequestHeaders["x-akto-payload-truncated"] = "true"
	}
	if entry.ResponseBodyTruncated {
		entry.ResponseHeaders["x-akto-payload-truncated"] = "true"
	}

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
		"akto_account_id": fmt.Sprint(1000000),
		"akto_vxlan_id":   fmt.Sprint(0),
		"is_pending":      fmt.Sprint(false),
		"source":          "MIRRORING",
		"direction":       fmt.Sprint(1),
	}

	// Debug: Print the Kafka message being sent
	msgBytes, _ := json.MarshalIndent(trafficData, "", "  ")
	log.Printf("KAFKA MESSAGE BEING SENT:\n%s\n", string(msgBytes))

	log.Printf("Sending traffic to Kafka for request_id=%s path=%s", entry.RequestID, entry.ResourcePath)
	kafkaUtil.ParseAndProduce(trafficData)
}
