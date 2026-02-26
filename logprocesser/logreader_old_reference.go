//go:build ignore
// +build ignore

// This file contains the OLD token-based log monitoring implementation.
// Kept for reference only — not compiled. The new timestamp-based approach
// is in logreader.go and fixes the pagination/stream-miss bugs.

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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

type StreamTracker struct {
	NextToken   *string
	LastChecked time.Time
	Active      bool
	logs        map[string]*LogEntry
}

func minOld(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func MonitorLogGroupOld(ctx context.Context, client *cloudwatchlogs.Client, logGroupName string) error {
	activeStreams := make(map[string]*StreamTracker)

	var nextLogStreamsToken *string

	for {
		logStreams, newNextToken, err := fetchLogStreamsOld(ctx, client, logGroupName, nextLogStreamsToken)
		if err != nil {
			log.Printf("Error fetching log streams: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}

		if newNextToken != nil {
			log.Printf("DEBUG New streams token found: %s for log group: %s", *newNextToken, logGroupName)
			nextLogStreamsToken = newNextToken
		} else {
			log.Printf("DEBUG No new streams token (pagination complete), clearing stream list for log group: %s", logGroupName)
			logStreams = []types.LogStream{}
		}

		log.Printf("DEBUG Processing %d log streams from batch. Log group: %s", len(logStreams), logGroupName)
		for _, stream := range logStreams {
			if _, exists := activeStreams[*stream.LogStreamName]; !exists {
				log.Printf("Discovered new log stream: %s (lastEventTimestamp: %v)", *stream.LogStreamName, stream.LastEventTimestamp)
				activeStreams[*stream.LogStreamName] = &StreamTracker{
					NextToken:   nil,
					LastChecked: time.Now(),
					Active:      true,
					logs:        make(map[string]*LogEntry),
				}
			}
		}
		log.Printf("DEBUG Total active streams: %d for log group: %s", len(activeStreams), logGroupName)

		for streamName, tracker := range activeStreams {
			if !tracker.Active {
				continue
			}

			err := processLogStreamOld(ctx, client, logGroupName, streamName, tracker)
			if err != nil {
				log.Printf("Error processing stream %s: %v", streamName, err)
			} else {
				tracker.LastChecked = time.Now()
			}

			if tracker.NextToken == nil || time.Since(tracker.LastChecked) > 10*time.Second {
				tracker.Active = false
				log.Printf("Marking stream as inactive, time interval exceeded: %s for log group: %s", streamName, logGroupName)
			}
		}

		for streamName, tracker := range activeStreams {
			if !tracker.Active {
				for logId, log := range tracker.logs {
					fmt.Printf("logId: %s\n", logId)
					fmt.Printf("log: %v\n", log)
					ParseAndProduce(*log)
				}

				delete(activeStreams, streamName)
				log.Printf("Removed inactive stream: %s", streamName)
			}
		}

		time.Sleep(1 * time.Second)
	}
}

func fetchLogStreamsOld(ctx context.Context, client *cloudwatchlogs.Client, logGroupName string, nextToken *string) ([]types.LogStream, *string, error) {
	output, err := client.DescribeLogStreams(ctx, &cloudwatchlogs.DescribeLogStreamsInput{
		LogGroupIdentifier: aws.String(logGroupName),
		OrderBy:            types.OrderByLastEventTime,
		Descending:         aws.Bool(false),
		Limit:              aws.Int32(int32(cloudwatchReadBatchSize)),
		NextToken:          nextToken,
	})
	if err != nil {
		return nil, nil, err
	}

	return output.LogStreams, output.NextToken, nil
}

func processLogStreamOld(ctx context.Context, client *cloudwatchlogs.Client, logGroupName, streamName string, tracker *StreamTracker) error {
	output, err := client.GetLogEvents(ctx, &cloudwatchlogs.GetLogEventsInput{
		LogGroupIdentifier: aws.String(logGroupName),
		LogStreamName:      aws.String(streamName),
		NextToken:          tracker.NextToken,
		StartFromHead:      aws.Bool(true),
	})
	if err != nil {
		log.Printf("Error getting log events from stream %s: %v", streamName, err)
		return err
	}

	log.Printf("DEBUG [%s] Got %d events. NextToken: %v → NextForwardToken: %v",
		streamName, len(output.Events), tracker.NextToken, output.NextForwardToken)

	eventsWithReqID := 0
	eventsWithoutReqID := 0

	for _, event := range output.Events {
		message := *event.Message

		var logEntry map[string]interface{}
		isJSON := false
		err := json.Unmarshal([]byte(message), &logEntry)

		var reqID string

		if err == nil {
			isJSON = true
			if reqIDVal, exists := logEntry["requestId"]; exists {
				if reqIDStr, ok := reqIDVal.(string); ok {
					reqID = reqIDStr
				}
			} else if extReqIDVal, exists := logEntry["extendedRequestId"]; exists {
				if extReqIDStr, ok := extReqIDVal.(string); ok {
					reqID = extReqIDStr
				}
			}
		} else {
			isJSON = false
			reqIDRegex := regexp.MustCompile(`\(([^)]+)\)`)
			matches := reqIDRegex.FindStringSubmatch(message)
			if len(matches) >= 2 {
				reqID = matches[1]
			}
		}

		if reqID == "" {
			eventsWithoutReqID++
			if eventsWithoutReqID <= 3 {
				log.Printf("DEBUG [%s] Could not parse request ID (sample %d): %s", streamName, eventsWithoutReqID, message[:minOld(200, len(message))])
			}
			continue
		}
		eventsWithReqID++

		if _, exists := tracker.logs[reqID]; !exists {
			tracker.logs[reqID] = &LogEntry{
				RequestID:       reqID,
				QueryParams:     make(map[string]string),
				RequestHeaders:  make(map[string]string),
				ResponseHeaders: make(map[string]string),
			}
		}

		entry := tracker.logs[reqID]

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
					entry.RequestBody = payloadStr
				}
			}

			if responsePayload, exists := logEntry["responsePayload"]; exists {
				if payloadStr, ok := responsePayload.(string); ok {
					entry.ResponseBody = payloadStr
				}
			}
		} else {
			httpMethodRegex := regexp.MustCompile(`HTTP Method:\s*(\S+),\s*Resource Path:\s*(\S+)`)

			if !strings.Contains(message, "TRUNCATED") {
				if strings.Contains(message, "HTTP Method:") && strings.Contains(message, "Resource Path:") {
					matches := httpMethodRegex.FindStringSubmatch(message)
					if len(matches) == 3 {
						entry.HTTPMethod = matches[1]
						entry.ResourcePath = matches[2]
					} else {
						fmt.Println("Error: Could not extract HTTP Method and Resource Path")
					}
				} else if strings.Contains(message, "Method request query string:") {
					entry.QueryParams = extractMap(message, "Method request query string:")
				} else if strings.Contains(message, "Method request headers:") {
					entry.RequestHeaders = extractMap(message, "Method request headers:")
				} else if strings.Contains(message, "Method request body before transformations:") {
					entry.RequestBody = extractBody(message, "Method request body before transformations:")
				} else if strings.Contains(message, "Method response headers:") {
					entry.ResponseHeaders = extractMap(message, "Method response headers:")
				} else if strings.Contains(message, "Method response body after transformations:") {
					entry.ResponseBody = extractBody(message, "Method response body after transformations:")
				} else if strings.Contains(message, "Method completed with status:") {
					parts := strings.Split(message, "Method completed with status:")
					if len(parts) > 1 {
						statusCodeStr := strings.TrimSpace(parts[1])
						statusCode, err := strconv.Atoi(statusCodeStr)
						if err == nil {
							entry.StatusCode = statusCode
						} else {
							fmt.Printf("Error converting status code to integer: %v\n", err)
						}
					} else {
						fmt.Println("Error: Could not find status code in the message")
					}
				}
			}
		}
	}

	log.Printf("DEBUG [%s] Summary: %d events with request IDs, %d without", streamName, eventsWithReqID, eventsWithoutReqID)

	if tracker.NextToken == nil || *tracker.NextToken != *output.NextForwardToken {
		tracker.NextToken = output.NextForwardToken
	} else {
		tracker.Active = false
		log.Printf("Marking stream as inactive, no new logs: %s", streamName)
	}

	return nil
}
