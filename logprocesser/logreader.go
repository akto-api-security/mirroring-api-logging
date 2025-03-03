package logprocesser

import (
	"context"
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
	now := time.Now().Unix()
	lastProcessedEventTime := now - 300
    utils.DebugLog("MonitorLogGroup() - Starting log processer for log group: %s", logGroupArn)
    utils.DebugLog("MonitorLogGroup() - Time now: %d", now)
    utils.DebugLog("MonitorLogGroup() - Starting Last processed event time: %d", lastProcessedEventTime)

	for {
		logStreams, err := FetchLogStreams(ctx, client, logGroupArn, lastProcessedEventTime)

		if err != nil {
            utils.DebugLog("MonitorLogGroup() - Error fetching log streams: %+v", err)
			continue
		}

        if(len(logStreams) == 0) {
            utils.DebugLog("MonitorLogGroup() - No new log streams found")
        }

		for _, stream := range logStreams {
            utils.DebugLog("MonitorLogGroup() - Processing log stream: %s", *stream.LogStreamName)
            utils.DebugLog("MonitorLogGroup() - Last event timestamp: %d", *stream.LastEventTimestamp)
            utils.DebugLog("MonitorLogGroup() - Last processed event time: %d", lastProcessedEventTime)
			if *stream.LastEventTimestamp > lastProcessedEventTime {
				events, err := getLogEvents(ctx, client, logGroupArn, *stream.LogStreamName, lastProcessedEventTime)

				if err != nil {
					continue
				}

				if len(events) > 0 {
					latestTimestamp := lastProcessedEventTime
					for _, event := range events {
						if *event.Timestamp > latestTimestamp {
							latestTimestamp = *event.Timestamp
						}
					}
					lastProcessedEventTime = latestTimestamp
				}
			}
		}

		elapsed := time.Now().Unix() - now
		if elapsed < 300 {
			time.Sleep(time.Duration(300-elapsed) * time.Second)
		} else {
			lastProcessedEventTime = now - 300
		}

        time.Sleep(1 * time.Second)
	}
}

func FetchLogStreams(ctx context.Context, client *cloudwatchlogs.Client, logGroupArn string, lastProcessedEventTime int64) ([]types.LogStream, error) {
    var logStreams []types.LogStream
    
    paginator := cloudwatchlogs.NewDescribeLogStreamsPaginator(client, &cloudwatchlogs.DescribeLogStreamsInput{
        LogGroupIdentifier: aws.String(logGroupArn),
        OrderBy:      types.OrderByLastEventTime,
        Descending:   aws.Bool(true),
    })
    
    for paginator.HasMorePages() {
        output, err := paginator.NextPage(ctx)
        if err != nil {
            return nil, err
        }
        
        for _, stream := range output.LogStreams {
            if stream.LastEventTimestamp != nil && *stream.LastEventTimestamp > lastProcessedEventTime {
                logStreams = append(logStreams, stream)
            }
        }
    }
    
    return logStreams, nil
}

func getLogEvents(ctx context.Context, client *cloudwatchlogs.Client, logGroupArn, logStreamName string, startTime int64) ([]types.OutputLogEvent, error) {
    utils.DebugLog("MonitorLogGroup() - Fetching log events for stream: %s", logStreamName)
    var logEvents []types.OutputLogEvent

	reqIDRegex := regexp.MustCompile(`\(([^)]+)\)`)
    httpMethodRegex := regexp.MustCompile(`HTTP Method:\s*(\S+),\s*Resource Path:\s*(\S+)`)
    
    paginator := cloudwatchlogs.NewGetLogEventsPaginator(client, &cloudwatchlogs.GetLogEventsInput{
        LogGroupIdentifier:  aws.String(logGroupArn),
        LogStreamName: aws.String(logStreamName),
        StartTime:     aws.Int64(startTime * 1000),
        EndTime:       aws.Int64(time.Now().Unix() * 1000),
    })

    utils.DebugLog("getLogEvents() - Logs paginator: %+v", *paginator)

    for paginator.HasMorePages() {
        output, err := paginator.NextPage(ctx)
        if err != nil {
            utils.DebugLog("getLogEvents() - Error in Logs paginator next page: %+v", err)
            return nil, err
        }

        utils.DebugLog("getLogEvents() - Logs paginator next page output: %+v", *output)
        
        for _, event := range output.Events {
            message := *event.Message
            matches := reqIDRegex.FindStringSubmatch(message)
            if len(matches) < 2 {
                utils.DebugLog("getLogEvents() - No request ID found in message: %s", message)
                continue
            }

            utils.DebugLog("getLogEvents() - Log message: %s", message)
            utils.DebugLog("getLogEvents() - Request ID: %s", matches[1])

            logEntry := LogEntry{
                RequestID: matches[1],
            }

            if !strings.Contains(message, "TRUNCATED") {
                if strings.Contains(message, "HTTP Method:") && strings.Contains(message, "Resource Path:") {
                    matches := httpMethodRegex.FindStringSubmatch(message)
                    if len(matches) == 3 {
                        logEntry.HTTPMethod = matches[1]
                        logEntry.ResourcePath = matches[2]
                        utils.DebugLog("getLogEvents() - HTTP Method: %s, Resource Path: %s", logEntry.HTTPMethod, logEntry.ResourcePath)
                    } else {
                        utils.DebugLog("getLogEvents() - Error parsing HTTP method and resource path: %s", message)
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
                        } else {
                            utils.DebugLog("Error converting status code to integer: %+v", err)
                        }
                    } else {
                        utils.DebugLog("Error: Could not find status code in the message: %s", message)
                    }
                }
            }

            utils.DebugLog("getLogEvents() - Log entry: %+v", logEntry)

            ParseAndProduce(logEntry)
        }
        
        logEvents = append(logEvents, output.Events...)
    }
    
    return logEvents, nil
}
