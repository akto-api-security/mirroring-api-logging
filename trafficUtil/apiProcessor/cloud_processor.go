package apiProcessor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

var (
	DefaultCloudTrafficProcessorMode = false
	DefaultCloudTrafficProcessorUrl  = "https:/cloud-processor.akto.io/ingestData"
	DefaultBufferIntervalSeconds     = 30
	DefaultBufferSize                = 100
	DefaultAuthenticationKey         = ""
)

func InitializeCloudTrafficProcessorConfig() (*CloudTrafficProcessorConfig, error) {
	slog.Warn("Cloud Processor initilization started")
	utils.InitVar("CLOUD_PROCESSOR_MODE", &DefaultCloudTrafficProcessorMode)
	if !DefaultCloudTrafficProcessorMode {
		slog.Warn("CLOUD_PROCESSOR_MODE is not set, defaulting to false")
		return nil, nil
	}

	utils.InitVar("CLOUD_PROCESSOR_AUTHENTICATION_KEY", &DefaultAuthenticationKey)
	if DefaultCloudTrafficProcessorMode {
		slog.Warn("Cloud Processor mode is enabled")
		if DefaultAuthenticationKey == "" {
			slog.Error("CLOUD_PROCESSOR_AUTHENTICATION_KEY is not set. Please set it to enable cloud processor mode.")
			os.Exit(1)
		} else {
			slog.Warn("CLOUD_PROCESSOR_AUTHENTICATION_KEY is set, proceeding with cloud processor mode")
		}

	}
	utils.InitVar("CLOUD_PROCESSOR_URL", &DefaultCloudTrafficProcessorUrl)

	utils.InitVar("CLOUD_PROCESSOR_BUFFER_INTERVAL_SECONDS", &DefaultBufferIntervalSeconds)
	utils.InitVar("CLOUD_PROCESSOR_BUFFER_SIZE", &DefaultBufferSize)
	config := &CloudTrafficProcessorConfig{
		CloudTrafficProcessorUrl: DefaultCloudTrafficProcessorUrl,
		BufferIntervalSeconds:    DefaultBufferIntervalSeconds,
		BufferSize:               DefaultBufferSize,
		AuthenticationKey:        DefaultAuthenticationKey,
	}
	return config, nil
}

type CloudTrafficProcessorConfig struct {
	CloudTrafficProcessorUrl string
	BufferIntervalSeconds    int
	BufferSize               int
	AuthenticationKey        string
}

type CloudTrafficProcessor struct {
	Config    CloudTrafficProcessorConfig
	DataQueue []map[string]string
}

func NewCloudTrafficProcessor() (*CloudTrafficProcessor, error) {
	config, err := InitializeCloudTrafficProcessorConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize the cloud traffic processor %v", err)
	}

	// Cloud traffic processing mode is not required.
	if config == nil {
		return nil, nil
	}

	return &CloudTrafficProcessor{
		Config:    *config,
		DataQueue: make([]map[string]string, config.BufferSize),
	}, nil
}

func (c *CloudTrafficProcessor) Produce(message map[string]string) {
	if c.DataQueue == nil {
		c.DataQueue = []map[string]string{}
	}

	c.DataQueue = append(c.DataQueue, message)

	if len(c.DataQueue) >= c.Config.BufferSize {
		go c.Flush() // Trigger flush asynchronously
	}
}

func (c *CloudTrafficProcessor) Flush() {
	if len(c.DataQueue) == 0 {
		slog.Warn("Flush called but data queue is empty")
		return
	}

	batchData := map[string]interface{}{
		"batchData": c.DataQueue,
	}

	batchDataJSON, err := json.Marshal(batchData)
	if err != nil {
		slog.Error("Failed to marshal batch data", "error", err)
		return
	}

	req, err := http.NewRequest("POST", c.Config.CloudTrafficProcessorUrl, bytes.NewBuffer(batchDataJSON))
	if err != nil {
		slog.Error("Failed to create HTTP request", "error", err)
		return
	}

	req.Header.Set("Authorization", c.Config.AuthenticationKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		slog.Error("Failed to send request to cloud processor", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Error("Cloud processor returned non-OK status", "status", resp.StatusCode)
		return
	}

	// Reset the data queue
	c.DataQueue = []map[string]string{}

	slog.Info("Successfully flushed data to cloud processor")
}

func (c *CloudTrafficProcessor) StartFlushTimer() {
	ticker := time.NewTicker(time.Duration(c.Config.BufferIntervalSeconds) * time.Second)
	go func() {
		for range ticker.C {
			slog.Info("Flush timer triggered")
			c.Flush()
		}
	}()
}
