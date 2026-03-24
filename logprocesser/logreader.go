package logprocesser

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/akto-api-security/api-gateway-logging/trafficUtil/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

var globalTimestampTracker = NewTimestampTracker()

const (
	POLL_DURATION         = 180000  // 3 minute in milliseconds
	LOG_STREAM_FETCH_TIME = 5400000 // 1.5 hours in milliseconds
	MAX_STREAM_MAP_SIZE   = 20000   // max entries in lastReadTimestamps map
)

// TimestampTracker tracks last read timestamp per log group + stream (same structure as temp_cred).
type TimestampTracker struct {
	mu                 sync.RWMutex
	lastReadTimestamps map[string]int64 // "logGroupName|streamName" -> last read timestamp ms
}

func NewTimestampTracker() *TimestampTracker {
	return &TimestampTracker{
		lastReadTimestamps: make(map[string]int64),
	}
}

func (t *TimestampTracker) GetLastReadTimestamp(logGroupName, streamName string) int64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.lastReadTimestamps[logGroupName+"|"+streamName]
}

func (t *TimestampTracker) UpdateLastReadTimestamp(logGroupName, streamName string, timestamp int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastReadTimestamps[logGroupName+"|"+streamName] = timestamp
	if len(t.lastReadTimestamps) > MAX_STREAM_MAP_SIZE {
		t.cleanupStaleEntries()
	}
}

func (t *TimestampTracker) cleanupStaleEntries() {
	cutoffTime := time.Now().UnixMilli() - LOG_STREAM_FETCH_TIME
	utils.LogToCyborg("info", fmt.Sprintf("TimestampTracker cleanup started at: %d and cutoffTime: %d", time.Now().UnixMilli(), cutoffTime))
	cleanedEntries := 0
	for key, ts := range t.lastReadTimestamps {
		if ts < cutoffTime {
			delete(t.lastReadTimestamps, key)
			cleanedEntries++
		}
	}
	utils.LogToCyborg("info", fmt.Sprintf("TimestampTracker cleanup completed, cleanedEntries: %d, entries: %d", cleanedEntries, len(t.lastReadTimestamps)))
}

// MonitorLogGroup monitors a CloudWatch log group (same structure as temp_cred; single-account).
func MonitorLogGroup(ctx context.Context, client *cloudwatchlogs.Client, logGroupName string) error {
	utils.DebugLog("MonitorLogGroup() - Starting log processor for log group: %s", logGroupName)

	for {
		cycleStartTime := time.Now().UnixMilli()
		utils.DebugLog("MonitorLogGroup() - Starting new monitoring cycle at: %d for logGroup: %s", cycleStartTime, logGroupName)

		lookBackTime := cycleStartTime - LOG_STREAM_FETCH_TIME
		logStreams, err := FetchLogStreams(ctx, client, logGroupName, lookBackTime)
		if err != nil {
			utils.LogToCyborg("error", "Error fetching log streams: "+err.Error())
			time.Sleep(10 * time.Second)
			continue
		}

		utils.DebugLog("MonitorLogGroup() - Found %d log streams to process for logGroup: %s", len(logStreams), logGroupName)

		for _, stream := range logStreams {
			streamName := *stream.LogStreamName
			lastReadTime := globalTimestampTracker.GetLastReadTimestamp(logGroupName, streamName)
			if lastReadTime == 0 {
				lastEventTs := "n/a"
				if stream.LastEventTimestamp != nil {
					lastEventTs = fmt.Sprint(*stream.LastEventTimestamp)
				}
				utils.LogToCyborg("info", fmt.Sprintf("Discovered new log stream: %s (lastEventTimestamp: %s); logGroup: %s", streamName, lastEventTs, logGroupName))
				// Limit to last 1 hour for new streams to avoid processing old data.
				lastReadTime = cycleStartTime - LOG_STREAM_FETCH_TIME
			}

			utils.DebugLog("MonitorLogGroup() - Processing stream: %s, reading from: %d for logGroup: %s", streamName, lastReadTime, logGroupName)

			eventCount, maxTimestamp, err := getLogEvents(ctx, client, logGroupName, streamName, lastReadTime)
			if err != nil {
				utils.LogToCyborg("error", "Error fetching log events for stream "+streamName+": "+err.Error())
				continue
			}

			if eventCount > 0 {
				globalTimestampTracker.UpdateLastReadTimestamp(logGroupName, streamName, maxTimestamp+1)
				utils.DebugLog("MonitorLogGroup() - Processed %d events from stream: %s, updated timestamp to: %d for logGroup: %s", eventCount, streamName, maxTimestamp+1, logGroupName)
			}
		}

		elapsed := time.Now().UnixMilli() - cycleStartTime
		log.Printf("MonitorLogGroup() - Cycle completed in %d ms, sleeping for %d ms for logGroup: %s", elapsed, POLL_DURATION-elapsed, logGroupName)
		if elapsed < POLL_DURATION {
			sleepTime := POLL_DURATION - elapsed
			time.Sleep(time.Duration(sleepTime) * time.Millisecond)
		}
		time.Sleep(10 * time.Second)
	}
}

// FetchLogStreams returns all streams with LastEventTimestamp > lastProcessedEventTime (temp_cred structure).
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
		if err != nil {
			utils.LogToCyborg("error", "Error fetching log streams: "+err.Error())
			return nil, err
		}

		foundOldStream := false
		for _, stream := range output.LogStreams {
			if stream.LastEventTimestamp == nil || *stream.LastEventTimestamp <= lastProcessedEventTime {
				foundOldStream = true
				break
			}
			logStreams = append(logStreams, stream)
		}

		if foundOldStream || output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return logStreams, nil
}

// getLogEvents fetches events from startTime to now, assembles by requestID using the original parsing logic, produces, returns event count and max timestamp (temp_cred structure).
func getLogEvents(ctx context.Context, client *cloudwatchlogs.Client, logGroupName, streamName string, startTime int64) (eventCount int, maxTimestamp int64, err error) {
	maxTimestamp = startTime
	logEntries := make(map[string]*LogEntry)
	var nextToken *string

	for {
		output, err := client.GetLogEvents(ctx, &cloudwatchlogs.GetLogEventsInput{
			LogGroupIdentifier: aws.String(logGroupName),
			LogStreamName:      aws.String(streamName),
			StartTime:          aws.Int64(startTime),
			EndTime:            aws.Int64(time.Now().UnixMilli()),
			NextToken:          nextToken,
			StartFromHead:      aws.Bool(true),
		})
		if err != nil {
			utils.LogToCyborg("error", "Error getting log events from stream "+streamName+": "+err.Error())
			return 0, maxTimestamp, err
		}

		if len(output.Events) == 0 {
			break
		}

		batchMax := ProcessEventsIntoLogEntries(output.Events, logGroupName, streamName, logEntries)
		if batchMax > maxTimestamp {
			maxTimestamp = batchMax
		}
		eventCount += len(output.Events)

		if output.NextForwardToken == nil {
			break
		}
		if nextToken != nil && *nextToken == *output.NextForwardToken {
			break
		}
		nextToken = output.NextForwardToken
	}

	for _, entry := range logEntries {
		ParseAndProduce(*entry)
	}
	return eventCount, maxTimestamp, nil
}
