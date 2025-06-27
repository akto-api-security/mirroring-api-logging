package utils

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

var printCounter = 1000

const (
	DirectionInbound  = 1
	DirectionOutbound = 2
)

/*
Initial 1000 logs, marking as warn.
Help in checking if the module started as expected.
*/
func PrintLog(val string, args ...any) {
	if printCounter > 0 {
		slog.Warn(val, args...)
		printCounter--
	}
}

var IgnoreIpTraffic = false
var IgnoreCloudMetadataCalls = false
var EnableGraph = false
var ThreatEnabled = false

func init() {
	SetupLogger()
	InitVar("AKTO_IGNORE_IP_TRAFFIC", &IgnoreIpTraffic)
	InitVar("AKTO_THREAT_ENABLED", &ThreatEnabled)
	InitVar("AKTO_IGNORE_CLOUD_METADATA_CALLS", &IgnoreCloudMetadataCalls)
	InitVar("AKTO_ENABLE_GRAPH", &EnableGraph)
}

func InitVar(envVarName string, targetVar interface{}) {
	envVar := os.Getenv(envVarName)
	if len(envVar) > 0 {
		switch v := targetVar.(type) {
		case *bool:
			*v = strings.ToLower(envVar) == "true"
			slog.Warn("Setting env value", "name", envVarName, "value", *v)
		case *string:
			*v = envVar
			slog.Warn("Setting env value", "name", envVarName, "value", *v)
		case *time.Duration:
			temp, err := time.ParseDuration(envVar + "s")
			if err == nil {
				*v = temp
				slog.Warn("Setting env value", "name", envVarName, "value", *v)
			}
		case *int:
			temp, err := strconv.Atoi(envVar)
			if err == nil {
				*v = temp
				slog.Warn("Setting env value", "name", envVarName, "value", *v)
			}
		default:
			slog.Warn("Unsupported type for targetVar", "type", v)
		}
	} else {
		slog.Warn("Missing env value, using default value", "name", envVarName)
	}
}

// Since akto runs in root mode in host pid namespace. We can read the environment variables of any process.
// For this function to work the processId must be kubernetes pod process id.
func ReadEnvVarForProcessId(envVarname string, processId uint64) (string, error) {
	filePath := "/proc/" + strconv.FormatUint(processId, 10) + "/environ"
	data, err := os.ReadFile(filePath)
	if err != nil {
		slog.Error("Failed to read environ file", "filePath", filePath, "error", err)
		return "", err
	}

	// Split the data by null character
	parts := strings.Split(string(data), "\x00")
	// Iterate through the parts to find the desired environment variable
	for _, part := range parts {
		if strings.HasPrefix(part, envVarname+"=") {
			// Return the value of the environment variable
			return strings.TrimPrefix(part, envVarname+"="), nil
		}
	}
	slog.Warn("Environment variable not found", "envVarname", envVarname, "processId", processId)
	return "", fmt.Errorf("environment variable not found")
}
