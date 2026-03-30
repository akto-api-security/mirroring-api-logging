package utils

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
)

// CyborgBaseURL is the base URL for the Cyborg API (Akto backend).
const CyborgBaseURL = "https://ultron.akto.io"

// LogEvent logs locally and optionally sends to Cyborg remote endpoint.
// level: "info", "warn", or "error"
// sendToCyborg: if true, also sends to Cyborg (non-blocking, fire-and-forget)
// Always logs locally to stdout/stderr.
func LogEvent(level string, message string, sendToCyborg bool) {
	// Always log locally
	log.Printf("[%s] %s", level, message)

	// Optionally send to Cyborg
	if sendToCyborg {
		SendLogToCyborg(level, message)
	}
}

// SendLogToCyborg sends an important log entry to the Cyborg remote logging endpoint.
// level: "info", "warn", or "error"
// Runs in a goroutine - non-blocking, fire-and-forget.
// Silently skips if DATABASE_ABSTRACTOR_TOKEN is not set.
func SendLogToCyborg(level string, message string) {
	go func() {
		token := os.Getenv("DATABASE_ABSTRACTOR_TOKEN")
		if token == "" {
			return
		}

		payload := map[string]interface{}{
			"log": map[string]interface{}{
				"log":       message,
				"key":       level,
				"timestamp": time.Now().Unix(),
			},
		}

		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			return
		}

		req, err := http.NewRequest("POST",
			CyborgBaseURL+"/api/insertAwsApiGatewayLog",
			bytes.NewBuffer(payloadJSON))
		if err != nil {
			return
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("authorization", token)

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
	}()
}

// LogToCyborg logs locally and sends to Cyborg (convenience function).
// Equivalent to: LogEvent(level, message, true)
func LogToCyborg(level string, message string) {
	LogEvent(level, message, true)
}

// LogLocal logs only locally (convenience function).
// Equivalent to: LogEvent(level, message, false)
func LogLocal(level string, message string) {
	LogEvent(level, message, false)
}
