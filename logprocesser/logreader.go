package logprocesser

import (
	"context"
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

func init() {
	utils.InitVar("CLOUDWATCH_READ_BATCH_SIZE", &cloudwatchReadBatchSize)
}

// MonitorLogGroup monitors a CloudWatch log group and processes events from its streams.
func MonitorLogGroup(ctx context.Context, client *cloudwatchlogs.Client, logGroupArn string) error {
	utils.DebugLog("Monitoring log group: %s", logGroupArn)
	activeStreams := make(map[string]*StreamTracker)

	var nextLogStreamsToken *string

	for {
		// Step 1: Fetch log streams with pagination using nextToken
		logStreams, newNextToken, err := fetchLogStreams(ctx, client, logGroupArn, nextLogStreamsToken)
		if err != nil {
			log.Printf("Error fetching log streams: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}

		// Update the next token for log streams pagination
		if newNextToken != nil {
			fmt.Printf("new streams found %s \n", *newNextToken)
			nextLogStreamsToken = newNextToken
		} else {
			// if newNextToken is nil,
			// means there are no new messages, these are old messages, we've processed
			// so clear the log stream
			// or there are less than stream batch size messages.
			// so to avoid recalculating later, skip them for now
			fmt.Printf("no new streams found \n")
			logStreams = []types.LogStream{}
		}

		// Step 2: Add new log streams to the active list
		for _, stream := range logStreams {
			utils.DebugLog("logStream: %+v", stream)
			if _, exists := activeStreams[*stream.LogStreamName]; !exists {
				log.Printf("Discovered new log stream: %s", *stream.LogStreamName)
				activeStreams[*stream.LogStreamName] = &StreamTracker{
					NextToken:   nil,
					LastChecked: time.Now(),
					Active:      true,
					logs:        make(map[string]*LogEntry),
				}
			}
		}

		// Step 3: Process logs from active streams
		for streamName, tracker := range activeStreams {
			utils.DebugLog("Processing stream: %s", streamName)
			utils.DebugLog("Tracker: %+v", tracker)
			if !tracker.Active {
				utils.DebugLog("Skipping inactive stream: %s", streamName)
				continue // Skip inactive streams
			}

			err := processLogStream(ctx, client, logGroupArn, streamName, tracker)
			if err != nil {
				log.Printf("Error processing stream %s: %v", streamName, err)
			} else {
				tracker.LastChecked = time.Now()
			}

			utils.DebugLog("Is stream in tracker inactive: %+v", tracker)
			// Mark the stream as inactive if no new logs are found and a new stream exists
			if tracker.NextToken == nil || time.Since(tracker.LastChecked) > 10*time.Second {
				utils.DebugLog("Tracker: %+v", tracker)
				tracker.Active = false
				log.Printf("Marking stream as inactive, time interval exceeded: %s", streamName)
			}
		}

		// Step 4: Clean up inactive streams
		for streamName, tracker := range activeStreams {
			utils.DebugLog("Checking stream: %s", streamName)
			utils.DebugLog("Is log stream active in tracker: %+v", tracker)
			if !tracker.Active {

				for logId, log := range tracker.logs {
					fmt.Printf("logId: %s\n", logId)
					fmt.Printf("log: %v\n", log)
					ParseAndProduce(*log)
				}

				log.Printf("Removing inactive stream: %s", streamName)
				delete(activeStreams, streamName)
				log.Printf("Removed inactive stream: %s", streamName)
			}
		}

		// Step 5: Delay between iterations to minimize API throttling
		time.Sleep(1 * time.Second)
	}
}

// fetchLogStreams retrieves log streams with pagination using nextToken.
func fetchLogStreams(ctx context.Context, client *cloudwatchlogs.Client, logGroupArn string, nextToken *string) ([]types.LogStream, *string, error) {
	// starting from the oldest logs
	output, err := client.DescribeLogStreams(ctx, &cloudwatchlogs.DescribeLogStreamsInput{
		LogGroupIdentifier: aws.String(logGroupArn),
		OrderBy:      types.OrderByLastEventTime,
		Descending:   aws.Bool(false),
		Limit:        aws.Int32(int32(cloudwatchReadBatchSize)), // Adjust based on expected stream count
		NextToken:    nextToken,
	})
	if err != nil {
		utils.DebugLog("fetchLogStreams() - Error fetching log streams: %+v", err)
		return nil, nil, err
	}

	utils.DebugLog("fetchLogStreams() - Log streams output: %+v", output)
	utils.DebugLog("fetchLogStreams() - Log streams: %+v", output.LogStreams)
	utils.DebugLog("fetchLogStreams() - Next token: %s", *output.NextToken)

	return output.LogStreams, output.NextToken, nil
}

// processLogStream reads and processes logs from a specific log stream using nextToken for pagination.
func processLogStream(ctx context.Context, client *cloudwatchlogs.Client, logGroupArn, streamName string, tracker *StreamTracker) error {
	output, err := client.GetLogEvents(ctx, &cloudwatchlogs.GetLogEventsInput{
		LogGroupIdentifier:  aws.String(logGroupArn),
		LogStreamName: aws.String(streamName),
		NextToken:     tracker.NextToken,
		StartFromHead: aws.Bool(true),
	})
	if err != nil {
		utils.DebugLog("processLogStream() - Error fetching log events: %+v", err)
		return err
	}

	reqIDRegex := regexp.MustCompile(`\(([^)]+)\)`)
	// Print log events
	for _, event := range output.Events {

		message := *event.Message
		matches := reqIDRegex.FindStringSubmatch(message)
		if len(matches) < 2 {
			utils.DebugLog("processLogStream() - No request ID found in message: %s", message)
			continue // Skip if no request ID found
		}

		reqID := matches[1]

		// fmt.Printf("reqId: %s\n", reqID)

		// Initialize a LogEntry for this req-id if it doesn't exist
		if _, exists := tracker.logs[reqID]; !exists {
			tracker.logs[reqID] = &LogEntry{
				RequestID:       reqID,
				QueryParams:     make(map[string]string),
				RequestHeaders:  make(map[string]string),
				ResponseHeaders: make(map[string]string),
			}
		}

		entry := tracker.logs[reqID]

		httpMethodRegex := regexp.MustCompile(`HTTP Method:\s*(\S+),\s*Resource Path:\s*(\S+)`)

		utils.DebugLog("processLogStream(): Message: %s", message)
		if !strings.Contains(message, "TRUNCATED") {
			if strings.Contains(message, "HTTP Method:") && strings.Contains(message, "Resource Path:") {
				fmt.Printf("scanning method: %s\n", message)

				// Use regex to extract HTTP Method and Resource Path
				matches := httpMethodRegex.FindStringSubmatch(message)
				if len(matches) == 3 { // First match is the full string, then two capture groups
					entry.HTTPMethod = matches[1]
					entry.ResourcePath = matches[2]
					fmt.Printf("scanned method: %s %s\n", entry.HTTPMethod, entry.ResourcePath)
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
				// Split the message into parts and extract the status code
				parts := strings.Split(message, "Method completed with status:")
				if len(parts) > 1 {
					statusCodeStr := strings.TrimSpace(parts[1]) // Extract the part after "status:"
					statusCode, err := strconv.Atoi(statusCodeStr)
					if err == nil {
						entry.StatusCode = statusCode
						fmt.Printf("Parsed status code: %d\n", entry.StatusCode)
					} else {
						fmt.Printf("Error converting status code to integer: %v\n", err)
					}
				} else {
					fmt.Println("Error: Could not find status code in the message")
				}
			}
		}

		utils.DebugLog("Stream: %s, Timestamp: %d, Message: %s", streamName, *event.Timestamp, *event.Message)
	}

	// Update the next token for the stream
	if tracker.NextToken == nil || *tracker.NextToken != *output.NextForwardToken {
		tracker.NextToken = output.NextForwardToken
		utils.DebugLog("Updated next token for stream: %s", streamName)
	} else {
		// If no new logs, consider the stream inactive
		tracker.Active = false
		log.Printf("Marking stream as inactive, no new logs: %s", streamName)
	}

	return nil
}
