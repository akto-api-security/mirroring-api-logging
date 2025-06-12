package apiProcessor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	utils "github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

var (
	CloudTrafficProcessorModeEnabled = false
	DefaultCloudTrafficProcessorUrl  = "https://cloudprocessor.akto.io/api/ingestData"
	DefaultFlushInterval             = time.Duration(30) * time.Second
	DefaultBufferSize                = 100
	DefaultAuthenticationToken       = ""
)

var CloudProcessorInstance *CloudTrafficProcessor
var CloudProcessorConfig *CloudTrafficProcessorConfig

type CloudTrafficProcessorConfig struct {
	CloudTrafficProcessorUrl string
	FlushInterval            time.Duration
	BufferSize               int
	AuthenticationToken      string
}

type CloudTrafficProcessor struct {
	Config        CloudTrafficProcessorConfig
	DataQueue     []map[string]string
	LastFlushTime time.Time
	mu            sync.Mutex
}

func InitializeCloudTrafficProcessorConfig() error {
	slog.Warn("Cloud Processor initialization started")
	utils.InitVar("CLOUD_PROCESSOR_MODE", &CloudTrafficProcessorModeEnabled)

	if !CloudTrafficProcessorModeEnabled {
		slog.Warn("CLOUD_PROCESSOR_MODE is not set, defaulting to false")
		return nil
	}

	utils.InitVar("CLOUD_PROCESSOR_AUTHENTICATION_TOKEN", &DefaultAuthenticationToken)
	slog.Warn("Cloud Processor mode is enabled")

	if DefaultAuthenticationToken == "" {
		return fmt.Errorf("authentication CLOUD_PROCESSOR_AUTHENTICATION_TOKEN missing")
	} else {
		slog.Warn("CLOUD_PROCESSOR_AUTHENTICATION_TOKEN is set, proceeding with cloud processor mode")
	}

	utils.InitVar("CLOUD_PROCESSOR_URL", &DefaultCloudTrafficProcessorUrl)
	utils.InitVar("CLOUD_PROCESSOR_BUFFER_INTERVAL_SECONDS", &DefaultFlushInterval)
	utils.InitVar("CLOUD_PROCESSOR_BUFFER_SIZE", &DefaultBufferSize)

	CloudProcessorConfig = &CloudTrafficProcessorConfig{
		CloudTrafficProcessorUrl: DefaultCloudTrafficProcessorUrl,
		FlushInterval:            DefaultFlushInterval,
		BufferSize:               DefaultBufferSize,
		AuthenticationToken:      DefaultAuthenticationToken,
	}
	return nil
}

func InitCloudTrafficProcessor() {
	if err := NewCloudTrafficProcessor(); err != nil {
		slog.Error("Failed to initialize CloudTrafficProcessor", "error", err)
		os.Exit(1)
	} else {
		slog.Info("CloudTrafficProcessor initialized successfully")
	}
}

func NewCloudTrafficProcessor() error {
	err := InitializeCloudTrafficProcessorConfig()
	if err != nil {
		return fmt.Errorf("failed to initialize the cloud traffic processor %v", err)
	}
	// Cloud traffic processing mode is not required.
	if !CloudTrafficProcessorModeEnabled {
		return nil
	}

	CloudProcessorInstance = &CloudTrafficProcessor{
		Config:        *CloudProcessorConfig,
		DataQueue:     make([]map[string]string, 0),
		LastFlushTime: time.Now(),
		mu:            sync.Mutex{},
	}
	return nil
}

func (c *CloudTrafficProcessor) Produce(message map[string]string) {

	if c == nil {
		return
	}

	if len(c.DataQueue) >= c.Config.BufferSize || time.Since(c.LastFlushTime) >= c.Config.FlushInterval {
		c.Flush()
	}

	slog.Debug("Producing message to CloudTrafficProcessor")

	c.DataQueue = append(c.DataQueue, message)

}

func (c *CloudTrafficProcessor) callIngestAPI(batchData map[string]interface{}) error {
	batchDataJSON, err := json.Marshal(batchData)
	if err != nil {
		return fmt.Errorf("failed to marshal batch data: %v", err)
	}

	req, err := http.NewRequest("POST", c.Config.CloudTrafficProcessorUrl, bytes.NewBuffer(batchDataJSON))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %v", err)
	}

	req.Header.Set("Authorization", c.Config.AuthenticationToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request to cloud processor: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("cloud processor returned non-OK status: %d", resp.StatusCode)
	}

	// json
	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("failed to decode JSON response for cloud processor: %v", err)
	}
	slog.Debug("Cloud processor response", "response", response)

	return nil
}

func (c *CloudTrafficProcessor) Flush() {
	slog.Debug("Flush called on CloudTrafficProcessor")
	c.mu.Lock()
	defer c.mu.Unlock()

	// Only one flush should be running at a time. Is this needed?
	sliceIndex := min(c.Config.BufferSize, len(c.DataQueue))

	if len(c.DataQueue) == 0 || sliceIndex == 0 {
		slog.Warn("Flush called but data queue is empty")
		return
	}

	batchData := map[string]interface{}{
		// slice the data queue to the configured buffer size
		"batchData": c.DataQueue[:sliceIndex],
	}

	err := c.callIngestAPI(batchData)
	if err != nil {
		// TODO what if this keeps failing ?
		slog.Error("Failed to flush data to cloud processor", "error", err)
		return
	}

	// Remove the flushed items from queue
	c.DataQueue = c.DataQueue[sliceIndex:]
	c.LastFlushTime = time.Now()

	slog.Debug("Successfully flushed data to cloud processor")
}
