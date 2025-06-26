package utils

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
)

const LevelOff = slog.Level(99)

var (
	ingestLogs   bool = false
	processLogs  bool = false
	aktoLogLevel string
	level        slog.Level = slog.LevelWarn
	logInterval  time.Duration = 120 * time.Second 
	lastCallTime time.Time
)

// create a function that returns false is 10 seconds have not passed since the last call

func SetupLogger() {
	fmt.Println("Setting up logger")
	InitVar("INGEST_LOGS", &ingestLogs)
	InitVar("PROCESS_LOGS", &processLogs)
	InitVar("AKTO_LOG_LEVEL", &aktoLogLevel)

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
	} else {
		level = slog.LevelWarn
	}

	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
		Level:     level,
	})

	fmt.Printf("Logger setup done with level %d and log level %s \n", level, aktoLogLevel)
	slog.SetDefault(slog.New(handler))
}

func LogIngest(format string, args ...any) {
	if ingestLogs {
		slog.Debug(format, args...)
	}
}

func LogProcessing(format string, args ...any) {
	if processLogs {
		slog.Debug(format, args...)
	}
}

// Returns false if 10 seconds have not passed since the last call
func HasLogIntervalPassed() bool {
	now := time.Now()
	if now.Sub(lastCallTime) < logInterval {
		return false
	}
	lastCallTime = now
	return true
}
