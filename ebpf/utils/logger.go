package utils

import (
	"log/slog"
	"os"
	"strings"
	trafficUtils "github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

const LevelOff = slog.Level(99)
var (
	ingestLogs  bool = false
	processLogs bool = false
	aktoLogLevel string
	level slog.Level = slog.LevelWarn
)

func init() {
	trafficUtils.InitVar("INGEST_LOGS", &ingestLogs)
	trafficUtils.InitVar("PROCESS_LOGS", &processLogs)
	trafficUtils.InitVar("AKTO_LOG_LEVEL", &aktoLogLevel)

	if aktoLogLevel != "" {
		switch strings.ToUpper(aktoLogLevel) {
		case "DEBUG":
			level = slog.LevelDebug
		case "INFO":
			level = slog.LevelInfo
		case "WARN":
			level = slog.LevelWarn
		case "ERROR":
			level = slog.LevelError
		case "OFF":
			level = LevelOff
		default:
			level = slog.LevelWarn
		}
	}else{
		level = slog.LevelWarn
	}

	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
		Level: level,
	})

	slog.SetDefault(slog.New(handler))
}

func LogIngest(format string, args ...interface{}) {
	if ingestLogs {
		slog.Debug(format, args...)
	}
}

func LogProcessing(format string, args ...interface{}) {
	if processLogs {
		slog.Debug(format, args...)
	}
}
