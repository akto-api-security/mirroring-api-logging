package utils

import (
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var (
	printCounter                   = 1000
	printCounterResetAt            = time.Now()
	TrafficLogBpfSocketDataSubmits = true
)

const (
	DirectionInbound  = 1
	DirectionOutbound = 2
	printCounterMax   = 100
	printCounterReset = 120 // seconds
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

// FastParser enables the zero-copy HTTP parse + JSON encode path in kafkaUtil.
// Best when each flush is a single request/response pair; multi-message buffers
// fall back to the legacy net/http parser.
var FastParser = false

// FastParserGunzip decompresses gzip response bodies on the fast path (allocates).
var FastParserGunzip = true

// FastParserChunkEncoding handles Transfer-Encoding: chunked on the fast path.
var FastParserChunkEncoding = true

const EnvoyProxyIp = "127.0.0.6"

// HostMappingPath is the root where the real host filesystem is visible (Docker: "/host"
// with -v /:/host; bare metal: "/").
var HostMappingPath = "/host"

// EbpfRootDir is the install root for the eBPF bundle (config, logs, BPF object layout).
var EbpfRootDir = "/ebpf"

// ResolveHostPath maps an absolute path on the real host (e.g. "/proc/1/exe") to the path
// this process should open (e.g. "/host/proc/1/exe" in Docker, "/proc/1/exe" on bare metal).
func ResolveHostPath(hostAbsPath string) string {
	if hostAbsPath == "" {
		return HostMappingPath
	}
	if HostMappingPath != "" && strings.HasPrefix(hostAbsPath, HostMappingPath) {
		return hostAbsPath
	}
	return HostMappingPath + hostAbsPath
}

// EbpfInstallPath joins path elements under EbpfRootDir.
func EbpfInstallPath(elem ...string) string {
	return filepath.Join(append([]string{EbpfRootDir}, elem...)...)
}

func init() {
	InitVar("HOST_MAPPING", &HostMappingPath)
	InitVar("EBPF_ROOT", &EbpfRootDir)
	SetupLogger()
	InitVar("AKTO_IGNORE_IP_TRAFFIC", &IgnoreIpTraffic)
	InitVar("AKTO_THREAT_ENABLED", &ThreatEnabled)
	InitVar("AKTO_IGNORE_CLOUD_METADATA_CALLS", &IgnoreCloudMetadataCalls)
	InitVar("AKTO_IGNORE_ENVOY_PROXY_CALLS", &IgnoreEnvoyProxycalls)
	InitVar("AKTO_ENABLE_GRAPH", &EnableGraph)
	InitVar("TRAFFIC_LOG_BPF_SOCKET_DATA_SUBMITS", &TrafficLogBpfSocketDataSubmits)
	InitVar("AKTO_FAST_PARSER", &FastParser)
	InitVar("AKTO_FAST_PARSER_GUNZIP", &FastParserGunzip)
	InitVar("AKTO_FAST_PARSER_CHUNK_ENCODING", &FastParserChunkEncoding)
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
