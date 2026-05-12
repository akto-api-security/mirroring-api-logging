package utils

import (
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

var printCounter = 1000
var printCounterResetAt = time.Now()

const (
	DirectionInbound  = 1
	DirectionOutbound = 2
	printCounterMax   = 1000
	printCounterReset = 60 // seconds
)

/*
Logs at WARN level with a budget that resets every minute.
*/
func PrintLog(val string, args ...any) {
	now := time.Now()
	if now.Sub(printCounterResetAt).Seconds() > printCounterReset {
		printCounter = printCounterMax
		printCounterResetAt = now
	}
	if printCounter > 0 {
		slog.Warn(val, args...)
		printCounter--
	}
}

/*
Print all debug logs as warn.
*/
func PrintLogDebug(val string, args ...any) {
	slog.Warn(val, args...)
}

var IgnoreIpTraffic = false
var IgnoreCloudMetadataCalls = false
var IgnoreEnvoyProxycalls = false
var EnableGraph = true
var ThreatEnabled = true

const EnvoyProxyIp = "127.0.0.6"

func init() {
	SetupLogger()
	InitVar("AKTO_IGNORE_IP_TRAFFIC", &IgnoreIpTraffic)
	InitVar("AKTO_THREAT_ENABLED", &ThreatEnabled)
	InitVar("AKTO_IGNORE_CLOUD_METADATA_CALLS", &IgnoreCloudMetadataCalls)
	InitVar("AKTO_IGNORE_ENVOY_PROXY_CALLS", &IgnoreEnvoyProxycalls)
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
		case *float64:
			temp, err := strconv.ParseFloat(envVar, 64)
			if err == nil {
				*v = temp
				slog.Warn("Setting env value", "name", envVarName, "value", *v)
			} else {
				slog.Warn("invalid float env, ignoring", "name", envVarName, "value", envVar, "error", err)
			}
		default:
			slog.Warn("Unsupported type for targetVar", "type", v)
		}
	} else {
	}
}
