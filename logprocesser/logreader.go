package logprocesser

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/akto-api-security/api-gateway-logging/trafficUtil/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

// StreamTracker tracks the progress and state of a log stream.
type StreamTracker struct {
	NextToken   *string
	LastChecked time.Time
	Active      bool
	logs        map[string]*LogEntry
}

var cloudwatchReadBatchSize = 5

// logStreamWindow is used only for the first run: lastDiscoveryTime is initialized to now - logStreamWindow.
var logStreamWindow = 1 * time.Hour

func init() {
	utils.InitVar("CLOUDWATCH_READ_BATCH_SIZE", &cloudwatchReadBatchSize)
}

// Helper function to get minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// MonitorLogGroup monitors a CloudWatch log group and processes events from its streams.
// Stream discovery uses DescribeLogStreams with Descending=true (newest first) and only
// considers streams with LastEventTimestamp >= lastDiscoveryTime (unprocessed since last discovery).
func MonitorLogGroup(ctx context.Context, client *cloudwatchlogs.Client, logGroupName string) error {
	activeStreams := make(map[string]*StreamTracker)
	lastDiscoveryTime := time.Now().Add(-logStreamWindow)

	for {
		windowStartMs := lastDiscoveryTime.UnixMilli()
		logStreams, err := fetchRecentLogStreams(ctx, client, logGroupName, windowStartMs)
		if err != nil {
			utils.LogToCyborg("error", "Error fetching log streams: "+err.Error())
			time.Sleep(2 * time.Second)
			continue
		}
		lastDiscoveryTime = time.Now()

		// Add new log streams to the active list
		log.Printf("DEBUG Processing %d log streams from batch. Log group: %s", len(logStreams), logGroupName)
		for _, stream := range logStreams {
			if _, exists := activeStreams[*stream.LogStreamName]; !exists {
				lastEventTs := "n/a"
				if stream.LastEventTimestamp != nil {
					lastEventTs = fmt.Sprint(*stream.LastEventTimestamp)
				}
				log.Printf("Discovered new log stream: %s (lastEventTimestamp: %v)", *stream.LogStreamName, stream.LastEventTimestamp)
				utils.LogToCyborg("info", fmt.Sprintf("Discovered new log stream: %s (lastEventTimestamp: %s)", *stream.LogStreamName, lastEventTs))
				activeStreams[*stream.LogStreamName] = &StreamTracker{
					NextToken:   nil,
					LastChecked: time.Now(),
					Active:      true,
					logs:        make(map[string]*LogEntry),
				}
			}
		}
		log.Printf("DEBUG Total active streams: %d for log group: %s", len(activeStreams), logGroupName)

		// Step 3: Process logs from active streams
		for streamName, tracker := range activeStreams {
			if !tracker.Active {
				log.Printf("Skipping inactive stream: %s (log group: %s)", streamName, logGroupName)
				continue // Skip inactive streams
			}

			err := processLogStream(ctx, client, logGroupName, streamName, tracker)
			if err != nil {
				utils.LogToCyborg("error", "Error processing stream "+streamName+": "+err.Error())
			} else {
				tracker.LastChecked = time.Now()
			}

			// Mark the stream as inactive if no new logs are found and a new stream exists
			if tracker.NextToken == nil || time.Since(tracker.LastChecked) > 10*time.Second {
				tracker.Active = false
			}
		}

		// Step 4: Clean up inactive streams
		for streamName, tracker := range activeStreams {
			if !tracker.Active {
				log.Printf("Flushing %d completed request(s) from stream %s (log group: %s)", len(tracker.logs), streamName, logGroupName)
				for logId, entry := range tracker.logs {
					log.Printf("logId: %s", logId)
					log.Printf("log: %v", entry)
					ParseAndProduce(*entry)
				}

				delete(activeStreams, streamName)
			}
		}

		// Step 5: Delay between iterations to minimize API throttling
		time.Sleep(1 * time.Second)
	}
}

// fetchLogStreamsPage retrieves one page of log streams ordered by LastEventTime descending (newest first).
// Limit is not set; API default and max is 50.
func fetchLogStreamsPage(ctx context.Context, client *cloudwatchlogs.Client, logGroupName string, nextToken *string) ([]types.LogStream, *string, error) {
	input := &cloudwatchlogs.DescribeLogStreamsInput{
		LogGroupIdentifier: aws.String(logGroupName),
		OrderBy:            types.OrderByLastEventTime,
		Descending:         aws.Bool(true),
		NextToken:          nextToken,
	}
	output, err := client.DescribeLogStreams(ctx, input)
	if err != nil {
		return nil, nil, err
	}
	return output.LogStreams, output.NextToken, nil
}

// fetchRecentLogStreams returns streams with LastEventTimestamp >= windowStartMs by paginating
// newest-first and stopping when a stream is older than the window (or pagination ends).
func fetchRecentLogStreams(ctx context.Context, client *cloudwatchlogs.Client, logGroupName string, windowStartMs int64) ([]types.LogStream, error) {
	var result []types.LogStream
	var nextToken *string
	for {
		page, newNextToken, err := fetchLogStreamsPage(ctx, client, logGroupName, nextToken)
		if err != nil {
			utils.LogToCyborg("error", "Error fetching log streams page: "+err.Error())
			return nil, err
		}
		for _, s := range page {
			if s.LastEventTimestamp != nil && *s.LastEventTimestamp < windowStartMs {
				return result, nil
			}
			if s.LastEventTimestamp == nil || *s.LastEventTimestamp >= windowStartMs {
				result = append(result, s)
			}
		}
		if newNextToken == nil {
			return result, nil
		}
		nextToken = newNextToken
	}
}

// processLogStream reads and processes logs from a specific log stream using nextToken for pagination.
func processLogStream(ctx context.Context, client *cloudwatchlogs.Client, logGroupName, streamName string, tracker *StreamTracker) error {
	log.Printf("Processing log stream: %s (log group: %s)", streamName, logGroupName)
	output, err := client.GetLogEvents(ctx, &cloudwatchlogs.GetLogEventsInput{
		LogGroupIdentifier: aws.String(logGroupName),
		LogStreamName:      aws.String(streamName),
		NextToken:          tracker.NextToken,
		StartFromHead:      aws.Bool(true),
	})
	if err != nil {
		utils.LogToCyborg("error", "Error getting log events from stream "+streamName+": "+err.Error())
		return err
	}

	log.Printf("DEBUG [%s] Got %d events. NextToken: %v → NextForwardToken: %v",
		streamName, len(output.Events), tracker.NextToken, output.NextForwardToken)

	// Try to parse JSON format first (API Gateway access logs)
	// Fall back to regex for execution logs
	eventsWithReqID := 0
	eventsWithoutReqID := 0

	for _, event := range output.Events {
		message := *event.Message

		// Try parsing as JSON first
		var logEntry map[string]interface{}
		isJSON := false
		err := json.Unmarshal([]byte(message), &logEntry)

		var reqID string

		if err == nil {
			isJSON = true
			// Successfully parsed as JSON - look for requestId field
			if reqIDVal, exists := logEntry["requestId"]; exists {
				if reqIDStr, ok := reqIDVal.(string); ok {
					reqID = reqIDStr
					log.Printf("DEBUG [%s] Parsed JSON format - requestId: %s", streamName, reqID)
				}
			} else if extReqIDVal, exists := logEntry["extendedRequestId"]; exists {
				// Fallback to extendedRequestId if requestId not found
				if extReqIDStr, ok := extReqIDVal.(string); ok {
					reqID = extReqIDStr
					log.Printf("DEBUG [%s] Parsed JSON format - extendedRequestId: %s", streamName, reqID)
				}
			}
		} else {
			// Fall back to regex for execution log format
			isJSON = false
			reqIDRegex := regexp.MustCompile(`\(([^)]+)\)`)
			matches := reqIDRegex.FindStringSubmatch(message)
			if len(matches) >= 2 {
				reqID = matches[1]
			}
		}

		if reqID == "" {
			eventsWithoutReqID++
			// Log first few messages to see what we're getting
			if eventsWithoutReqID <= 3 {
				log.Printf("DEBUG [%s] Could not parse request ID (sample %d): %s", streamName, eventsWithoutReqID, message[:min(200, len(message))])
			}
			continue // Skip if no request ID found
		}
		eventsWithReqID++

		// fmt.Printf("reqId: %s\n", reqID)

		// Initialize a LogEntry for this req-id if it doesn't exist
		if _, exists := tracker.logs[reqID]; !exists {
			tracker.logs[reqID] = &LogEntry{
				RequestID:          reqID,
				QueryParams:        make(map[string]string),
				RequestHeaders:     make(map[string]string),
				ResponseHeaders:    make(map[string]string),
				LogGroupIdentifier: logGroupName,
			}
		}

		entry := tracker.logs[reqID]

		// If JSON format, extract data from JSON fields
		if isJSON && err == nil {
			// Extract HTTP method (try multiple field names)
			if httpMethod, exists := logEntry["httpMethod"]; exists {
				if httpMethodStr, ok := httpMethod.(string); ok {
					entry.HTTPMethod = httpMethodStr
				}
			} else if method, exists := logEntry["method"]; exists {
				if methodStr, ok := method.(string); ok {
					entry.HTTPMethod = methodStr
				}
			}

			// Extract resource path (try multiple field names)
			if resourcePath, exists := logEntry["resourcePath"]; exists {
				if resourcePathStr, ok := resourcePath.(string); ok {
					entry.ResourcePath = resourcePathStr
				}
			} else if path, exists := logEntry["path"]; exists {
				if pathStr, ok := path.(string); ok {
					entry.ResourcePath = pathStr
				}
			}

			// Extract status code (try multiple field names and types)
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

			// Extract request headers
			if headers, exists := logEntry["headers"]; exists {
				if headersMap, ok := headers.(map[string]interface{}); ok {
					for k, v := range headersMap {
						if vStr, ok := v.(string); ok {
							entry.RequestHeaders[k] = vStr
						}
					}
				}
			}

			// Extract response headers
			if responseHeaders, exists := logEntry["responseHeaders"]; exists {
				if headersMap, ok := responseHeaders.(map[string]interface{}); ok {
					for k, v := range headersMap {
						if vStr, ok := v.(string); ok {
							entry.ResponseHeaders[k] = vStr
						}
					}
				}
			}

			// Extract request payload/body and handle truncation
			if requestPayload, exists := logEntry["requestPayload"]; exists {
				if payloadStr, ok := requestPayload.(string); ok {
					repairedBody, wasTruncated := RepairTruncatedJSON(payloadStr)
					entry.RequestBody = repairedBody
					if wasTruncated {
						entry.RequestBodyTruncated = true
					}
				}
			}

			// Extract response payload/body and handle truncation
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
				// Debug: Show what headers/payloads were extracted
				if len(entry.RequestHeaders) > 0 {
					log.Printf("DEBUG [%s]   RequestHeaders: %v", streamName, entry.RequestHeaders)
				}
				if len(entry.ResponseHeaders) > 0 {
					log.Printf("DEBUG [%s]   ResponseHeaders: %v", streamName, entry.ResponseHeaders)
				}
				if entry.RequestBody != "" {
					log.Printf("DEBUG [%s]   RequestBody: %s", streamName, entry.RequestBody[:min(100, len(entry.RequestBody))])
				}
				if entry.ResponseBody != "" {
					log.Printf("DEBUG [%s]   ResponseBody: %s", streamName, entry.ResponseBody[:min(100, len(entry.ResponseBody))])
				}
			}
		} else {
			// Fall back to regex pattern matching for execution logs
			httpMethodRegex := regexp.MustCompile(`HTTP Method:\s*(\S+),\s*Resource Path:\s*(\S+)`)

			if strings.Contains(message, "HTTP Method:") && strings.Contains(message, "Resource Path:") {
				matches := httpMethodRegex.FindStringSubmatch(message)
				if len(matches) == 3 {
					entry.HTTPMethod = matches[1]
					entry.ResourcePath = matches[2]
				} else {
					log.Println("Error: Could not extract HTTP Method and Resource Path")
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
						log.Printf("Error converting status code to integer: %v", err)
					}
				} else {
					log.Println("Error: Could not find status code in the message")
				}
			}
		}
	}

	log.Printf("DEBUG [%s] Summary: %d events with request IDs, %d without", streamName, eventsWithReqID, eventsWithoutReqID)

	// Update the next token for the stream
	if tracker.NextToken == nil || *tracker.NextToken != *output.NextForwardToken {
		log.Printf("DEBUG [%s] Token changed or initial read. Updating token from %v to %v", streamName, tracker.NextToken, output.NextForwardToken)
		tracker.NextToken = output.NextForwardToken
	} else {
		// If no new logs, consider the stream inactive
		log.Printf("DEBUG [%s] Token unchanged (%v == %v), marking as inactive", streamName, *tracker.NextToken, *output.NextForwardToken)
		tracker.Active = false
	}

	return nil
}
