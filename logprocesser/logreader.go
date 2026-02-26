package logprocesser

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/akto-api-security/api-gateway-logging/trafficUtil/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

var cloudwatchReadBatchSize = 5
var globalTimestampTracker = NewTimestampTracker()

const POLL_DURATION = 20000           // 20 seconds in milliseconds (for testing; use 300000 for production)
const LOG_STREAM_FETCH_TIME = 5400000 // 1.5 hours in milliseconds
const MAX_STREAM_MAP_SIZE = 10000

type TimestampTracker struct {
	mu                 sync.RWMutex
	lastReadTimestamps map[string]int64 // "logGroup|streamName" -> last read timestamp
}

func NewTimestampTracker() *TimestampTracker {
	return &TimestampTracker{
		lastReadTimestamps: make(map[string]int64),
	}
}

func (t *TimestampTracker) GetLastReadTimestamp(logGroup, streamName string) int64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	key := logGroup + "|" + streamName
	return t.lastReadTimestamps[key]
}

func (t *TimestampTracker) UpdateLastReadTimestamp(logGroup, streamName string, timestamp int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := logGroup + "|" + streamName
	t.lastReadTimestamps[key] = timestamp

	if len(t.lastReadTimestamps) > MAX_STREAM_MAP_SIZE {
		t.cleanupStaleEntries()
	}
}

func (t *TimestampTracker) cleanupStaleEntries() {
	cutoffTime := time.Now().Unix()*1000 - LOG_STREAM_FETCH_TIME
	for key, timestamp := range t.lastReadTimestamps {
		if timestamp < cutoffTime {
			delete(t.lastReadTimestamps, key)
		}
	}
	utils.DebugLog("TimestampTracker cleanup completed, entries: %d", len(t.lastReadTimestamps))
}

func init() {
	utils.InitVar("CLOUDWATCH_READ_BATCH_SIZE", &cloudwatchReadBatchSize)
}

func MonitorLogGroup(ctx context.Context, client *cloudwatchlogs.Client, logGroupName string) error {
	utils.DebugLog("MonitorLogGroup() - Starting log processor for log group: %s", logGroupName)

	for {
		cycleStartTime := time.Now().Unix() * 1000
		utils.DebugLog("MonitorLogGroup() - Starting new monitoring cycle at: %d for logGroup: %s", cycleStartTime, logGroupName)

		lookBackTime := cycleStartTime - LOG_STREAM_FETCH_TIME
		logStreams, err := FetchLogStreams(ctx, client, logGroupName, lookBackTime)

		if err != nil {
			utils.DebugLog("MonitorLogGroup() - Error fetching log streams: %+v for logGroup: %s", err, logGroupName)
			time.Sleep(10 * time.Second)
			continue
		}

		utils.DebugLog("MonitorLogGroup() - Found %d log streams to process for logGroup: %s", len(logStreams), logGroupName)

		for _, stream := range logStreams {
			streamName := *stream.LogStreamName
			lastReadTime := globalTimestampTracker.GetLastReadTimestamp(logGroupName, streamName)

			if lastReadTime == 0 {
				lastReadTime = cycleStartTime - 2*POLL_DURATION
			}

			utils.DebugLog("MonitorLogGroup() - Processing stream: %s, reading from: %d for logGroup: %s", streamName, lastReadTime, logGroupName)

			events, maxTimestamp, err := getLogEvents(ctx, client, logGroupName, streamName, lastReadTime)
			if err != nil {
				utils.DebugLog("MonitorLogGroup() - Error fetching log events for stream %s: %+v for logGroup: %s", streamName, err, logGroupName)
				continue
			}

			if len(events) > 0 {
				maxTimestamp = maxTimestamp + 1
				globalTimestampTracker.UpdateLastReadTimestamp(logGroupName, streamName, maxTimestamp)
				utils.DebugLog("MonitorLogGroup() - Processed %d new events from stream: %s, updated timestamp to: %d for logGroup: %s", len(events), streamName, maxTimestamp, logGroupName)
			}
		}

		elapsed := time.Now().Unix()*1000 - cycleStartTime
		if elapsed < POLL_DURATION {
			sleepTime := POLL_DURATION - elapsed
			utils.DebugLog("MonitorLogGroup() - Cycle completed in %d ms, sleeping for %d ms for logGroup: %s", elapsed, sleepTime, logGroupName)
			time.Sleep(time.Duration(sleepTime) * time.Millisecond)
		}

		time.Sleep(10 * time.Second)
	}
}

func FetchLogStreams(ctx context.Context, client *cloudwatchlogs.Client, logGroupName string, lastProcessedEventTime int64) ([]types.LogStream, error) {
	var logStreams []types.LogStream
	var nextToken *string

	for {
		output, err := client.DescribeLogStreams(ctx, &cloudwatchlogs.DescribeLogStreamsInput{
			LogGroupIdentifier: aws.String(logGroupName),
			OrderBy:            types.OrderByLastEventTime,
			Descending:         aws.Bool(true),
			NextToken:          nextToken,
		})

		if output != nil {
			utils.DebugLog("FetchLogStreams() - Number of log streams fetched: %+v for logGroup: %s", len(output.LogStreams), logGroupName)
		}

		if err != nil {
			utils.DebugLog("FetchLogStreams() - Error fetching log streams: %+v for logGroup: %s", err, logGroupName)
			return nil, err
		}

		for _, stream := range output.LogStreams {
			if stream.LastEventTimestamp != nil && *stream.LastEventTimestamp > lastProcessedEventTime {
				utils.DebugLog("FetchLogStreams() - Adding log stream: %s, LastEventTimestamp: %d for logGroup: %s", *stream.LogStreamName, *stream.LastEventTimestamp, logGroupName)
				logStreams = append(logStreams, stream)
			}
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return logStreams, nil
}

func getLogEvents(ctx context.Context, client *cloudwatchlogs.Client, logGroupName, logStreamName string, startTime int64) ([]types.OutputLogEvent, int64, error) {
	utils.DebugLog("getLogEvents() - Fetching events for stream: %s, time start: %d for logGroup: %s", logStreamName, startTime, logGroupName)

	var logEvents []types.OutputLogEvent
	var maxTimestamp int64 = startTime

	reqIDRegex := regexp.MustCompile(`\(([^)]+)\)`)
	httpMethodRegex := regexp.MustCompile(`HTTP Method:\s*(\S+),\s*Resource Path:\s*(\S+)`)

	var nextToken *string

	for {
		output, err := client.GetLogEvents(ctx, &cloudwatchlogs.GetLogEventsInput{
			LogGroupIdentifier: aws.String(logGroupName),
			LogStreamName:      aws.String(logStreamName),
			StartTime:          aws.Int64(startTime),
			EndTime:            aws.Int64(time.Now().Unix() * 1000),
			NextToken:          nextToken,
		})

		if err != nil {
			return nil, maxTimestamp, err
		}

		if len(output.Events) == 0 {
			break
		}

		logEntries := make(map[string]LogEntry)

		for _, event := range output.Events {
			eventTime := *event.Timestamp
			if eventTime > maxTimestamp {
				maxTimestamp = eventTime
			}

			message := *event.Message
			matches := reqIDRegex.FindStringSubmatch(message)
			if len(matches) < 2 {
				continue
			}

			requestID := matches[1]

			logEntry, exists := logEntries[requestID]
			if !exists {
				logEntry = LogEntry{RequestID: requestID, RequestBody: "{}", ResponseBody: "{}"}
			}

			if strings.Contains(message, "Endpoint request body after transformations:") {
				extractEndpointRequestBody(message, &logEntry)
			} else if strings.Contains(message, "Endpoint response body before transformations:") {
				extractStatusCodeFromEndpointResponse(message, &logEntry)
			} else if !strings.Contains(message, "TRUNCATED") {
				if strings.Contains(message, "HTTP Method:") && strings.Contains(message, "Resource Path:") {
					matches := httpMethodRegex.FindStringSubmatch(message)
					if len(matches) == 3 {
						logEntry.HTTPMethod = matches[1]
						logEntry.ResourcePath = matches[2]
					}
				} else if strings.Contains(message, "Method request query string:") {
					logEntry.QueryParams = extractMap(message, "Method request query string:")
				} else if strings.Contains(message, "Method request headers:") {
					logEntry.RequestHeaders = extractMap(message, "Method request headers:")
				} else if strings.Contains(message, "Method request body before transformations:") {
					logEntry.RequestBody = extractBody(message, "Method request body before transformations:")
				} else if strings.Contains(message, "Method response headers:") {
					logEntry.ResponseHeaders = extractMap(message, "Method response headers:")
				} else if strings.Contains(message, "Method response body after transformations:") {
					logEntry.ResponseBody = extractBody(message, "Method response body after transformations:")
				} else if strings.Contains(message, "Method completed with status:") {
					parts := strings.Split(message, "Method completed with status:")
					if len(parts) > 1 {
						statusCodeStr := strings.TrimSpace(parts[1])
						statusCode, err := strconv.Atoi(statusCodeStr)
						if err == nil {
							logEntry.StatusCode = statusCode
						}
					}
				}
			}

			logEntries[requestID] = logEntry
		}

		for _, logEntry := range logEntries {
			ParseAndProduce(logEntry)
		}

		logEvents = append(logEvents, output.Events...)

		if output.NextForwardToken == nil || (nextToken != nil && *nextToken == *output.NextForwardToken) {
			break
		}
		nextToken = output.NextForwardToken
	}

	return logEvents, maxTimestamp, nil
}
