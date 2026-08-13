package utils

import (
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

// FastIngestion selects the whole processing flow, end to end. When true, the
// connection layer uses msg_seq incremental single-pair flushing AND kafkaUtil
// uses the zero-copy fast parser + encoder. When false, the old flow runs:
// inactivity/threshold flat-buffer flushing + the net/http parser. The two must
// move together — the fast parser assumes exactly one request/response pair per
// flush, which only msg_seq flushing guarantees.
var FastIngestion = true

// FastParserGunzip, when true, makes the fast parser decompress gzip response
// bodies (Content-Encoding: gzip) after de-chunking. Off by default because it
// allocates (decompression expands, so the body can't alias the input buffer) —
// the default fast path stays zero-copy/zero-alloc. Opt in when readable bodies
// matter more than the per-message decompression cost.
var FastParserGunzip = true

// Enable disable assembling bodies in parser when Transfer-Encoding: chunked, header
// is present. 
var HandleChunkEncoding = true

const EnvoyProxyIp = "127.0.0.6"

func init() {
	SetupLogger()
	InitVar("AKTO_IGNORE_IP_TRAFFIC", &IgnoreIpTraffic)
	InitVar("AKTO_THREAT_ENABLED", &ThreatEnabled)
	InitVar("AKTO_IGNORE_CLOUD_METADATA_CALLS", &IgnoreCloudMetadataCalls)
	InitVar("AKTO_IGNORE_ENVOY_PROXY_CALLS", &IgnoreEnvoyProxycalls)
	InitVar("AKTO_ENABLE_GRAPH", &EnableGraph)
	InitVar("AKTO_FAST_INGESTION", &FastIngestion)
	InitVar("AKTO_FAST_PARSER_GUNZIP", &FastParserGunzip)
	InitVar("AKTO_FAST_PARSER_CHUNK_ENCODING", &HandleChunkEncoding)
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
	}
}
