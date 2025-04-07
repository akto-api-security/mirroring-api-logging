package utils

import (
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

var printCounter = 500

func PrintLog(val string) {
	if printCounter > 0 {
		slog.Debug(val)
		printCounter--
	}
}

var IgnoreIpTraffic = false
var IgnoreCloudMetadataCalls = false

func init() {
	SetupLogger()
	InitVar("AKTO_IGNORE_IP_TRAFFIC", &IgnoreIpTraffic)
	InitVar("AKTO_IGNORE_CLOUD_METADATA_CALLS", &IgnoreCloudMetadataCalls)
}

func InitVar(envVarName string, targetVar interface{}) {
	envVar := os.Getenv(envVarName)
	if len(envVar) > 0 {
		switch v := targetVar.(type) {
		case *bool:
			*v = strings.ToLower(envVar) == "true"
			slog.Debug("Setting env value", "name", envVarName, "value", *v)
		case *string:
			*v = envVar
			slog.Debug("Setting env value", "name", envVarName, "value", *v)
		case *time.Duration:
			temp, err := time.ParseDuration(envVar + "s")
			if err == nil {
				*v = temp
				slog.Debug("Setting env value", "name", envVarName, "value", *v)
			}
		case *int:
			temp, err := strconv.Atoi(envVar)
			if err == nil {
				*v = temp
				slog.Debug("Setting env value", "name", envVarName, "value", *v)
			}		
		default:
			slog.Info("Unsupported type for targetVar", "type", v)
		}
	} else {
		slog.Info("Missing env value", "name", envVarName)
	}
}
