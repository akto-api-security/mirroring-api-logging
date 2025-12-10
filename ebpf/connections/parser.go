package connections

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/akto-api-security/guardrails-service/models"
	"github.com/akto-api-security/guardrails-service/pkg/config"
	"github.com/akto-api-security/guardrails-service/pkg/validator"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/kafkaUtil"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
	"go.uber.org/zap"
)

var (
	validatorService     *validator.Service
	validatorServiceOnce sync.Once
	validatorLogger      *zap.Logger
	validatorEnabled     = true
)

func init() {
	utils.InitVar("GUARDRAILS_ENABLED", &validatorEnabled)
}

// InitValidatorService initializes the guardrails validator service
// This should be called once during application startup
func InitValidatorService() error {
	var initErr error
	validatorServiceOnce.Do(func() {
		// Create logger
		var err error
		validatorLogger, err = zap.NewProduction()
		if err != nil {
			initErr = fmt.Errorf("failed to create logger: %w", err)
			return
		}

		// Load config from environment variables
		cfg := config.LoadConfig()

		// Create validator service
		validatorService, err = validator.NewService(cfg, validatorLogger)
		if err != nil {
			initErr = fmt.Errorf("failed to create validator service: %w", err)
			return
		}

		validatorLogger.Info("Guardrails validator service initialized successfully")
	})

	return initErr
}

// GetValidatorService returns the singleton validator service instance
func GetValidatorService() *validator.Service {
	return validatorService
}

// ValidateTraffic validates the captured traffic using guardrails service
func ValidateTraffic(batchData []models.IngestDataBatch) ([]validator.ValidationBatchResult, error) {
	if validatorService == nil {
		return nil, fmt.Errorf("validator service not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return validatorService.ValidateBatch(ctx, batchData)
}

// tryReadFromBD processes captured traffic data and optionally validates it using guardrails
func tryReadFromBD(ip string, destIp string, receiveBuffer []byte, sentBuffer []byte, isComplete bool, direction int, id uint64, fd uint32, daemonsetIdentifier, hostName string) {
	// Parse the HTTP request/response from buffers
	// sentBuffer contains the request (or response for egress)
	// receiveBuffer contains the response (or request for egress)

	requestPayload := string(sentBuffer)
	responsePayload := string(receiveBuffer)

	// Create batch data for validation
	batchData := models.IngestDataBatch{
		Path:            extractPath(requestPayload),
		Method:          extractMethod(requestPayload),
		RequestPayload:  requestPayload,
		ResponsePayload: responsePayload,
		IP:              ip,
		DestIP:          destIp,
		Time:            strconv.FormatInt(time.Now().UnixMilli(), 10),
		StatusCode:      extractStatusCode(responsePayload),
		Direction:       strconv.Itoa(direction),
		ProcessID:       strconv.FormatUint(id>>32, 10),
		SocketID:        strconv.FormatUint(uint64(fd), 10),
		DaemonsetID:     daemonsetIdentifier,
		Source:          "ebpf",
	}

	// If guardrails validation is enabled and service is initialized, validate the traffic
	if validatorEnabled && validatorService != nil {
		results, err := ValidateTraffic([]models.IngestDataBatch{batchData})
		if err != nil {
			utils.LogIngest("Guardrails validation failed", "error", err.Error())
		} else if len(results) > 0 {
			result := results[0]
			if !result.RequestAllowed {
				utils.LogIngest("Request blocked by guardrails",
					"path", batchData.Path,
					"method", batchData.Method,
					"reason", result.RequestReason)
				// Optionally skip sending to Kafka if blocked
				// return
			}
			if !result.ResponseAllowed {
				utils.LogIngest("Response blocked by guardrails",
					"path", batchData.Path,
					"method", batchData.Method,
					"reason", result.ResponseReason)
			}
		}
	}

	// Continue with existing Kafka processing
	// ParseAndProduce(receiveBuffer, sentBuffer, sourceIp, destIp, vxlanID, isPending, trafficSource, isComplete, direction, idfd, fd, daemonsetIdentifier, hostName)
	kafkaUtil.ParseAndProduce(receiveBuffer, sentBuffer, ip, destIp, 0, false, "ebpf", isComplete, direction, id, fd, daemonsetIdentifier, hostName)
}

// extractMethod extracts the HTTP method from the request payload
func extractMethod(payload string) string {
	if len(payload) == 0 {
		return ""
	}
	// HTTP request starts with METHOD /path HTTP/1.x
	for i, c := range payload {
		if c == ' ' {
			return payload[:i]
		}
	}
	return ""
}

// extractPath extracts the path from the HTTP request payload
func extractPath(payload string) string {
	if len(payload) == 0 {
		return ""
	}
	// HTTP request starts with METHOD /path HTTP/1.x
	firstSpace := -1
	secondSpace := -1
	for i, c := range payload {
		if c == ' ' {
			if firstSpace == -1 {
				firstSpace = i
			} else {
				secondSpace = i
				break
			}
		}
		if c == '\r' || c == '\n' {
			break
		}
	}
	if firstSpace != -1 && secondSpace != -1 {
		return payload[firstSpace+1 : secondSpace]
	}
	return ""
}

// extractStatusCode extracts the HTTP status code from the response payload
func extractStatusCode(payload string) string {
	if len(payload) < 12 {
		return ""
	}
	// HTTP response starts with HTTP/1.x STATUS_CODE ...
	// Example: HTTP/1.1 200 OK
	if payload[:4] == "HTTP" {
		// Find the status code after the first space
		firstSpace := -1
		secondSpace := -1
		for i := 0; i < len(payload) && i < 20; i++ {
			if payload[i] == ' ' {
				if firstSpace == -1 {
					firstSpace = i
				} else {
					secondSpace = i
					break
				}
			}
		}
		if firstSpace != -1 && secondSpace != -1 {
			return payload[firstSpace+1 : secondSpace]
		}
	}
	return ""
}
