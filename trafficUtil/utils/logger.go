package utils

import (
	"context"
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
	level        slog.Level    = slog.LevelWarn
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
	SetupAllFileLoggers()
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

var fileLoggers = make(map[string]*slog.Logger)
var fileHandlers = make(map[string]*os.File)
const HOST_MAPPING_PATH = "/host/var/log/akto/"

const (
	OSPidLogFile         = HOST_MAPPING_PATH + "ospidlog.txt"
	GoPidLogFile         = HOST_MAPPING_PATH + "gopidlog.txt"
	LabelsMapLogFile     = HOST_MAPPING_PATH + "labelsmaplog.txt"
	ResolveLabelsLogFile = HOST_MAPPING_PATH + "resolvelabels.txt"
)

func SetupFileLogger(filePath string, logLevel slog.Level) {
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	fileHandlers[filePath] = file
	if err != nil {
		fmt.Printf("Failed to open log file: %s, error: %v\n", filePath, err)
		return
	}

	handler := slog.NewTextHandler(file, &slog.HandlerOptions{
		AddSource: true,
		Level:     logLevel,
	})

	fileLoggers[filePath] = slog.New(handler)
	fmt.Printf("File logger setup done with level %d and file path %s\n", logLevel, filePath)
}

func LogToSpecificFile(filePath string, format string, args ...any) {
	logger, exists := fileLoggers[filePath]
	if !exists {
		fmt.Printf("Logger for file %s is not initialized\n", filePath)
		return
	}
	logger.Log(context.Background(), slog.LevelInfo, format, args...)

}

func SetupAllFileLoggers() {
	if _, err := os.Stat(HOST_MAPPING_PATH); os.IsNotExist(err) {
		os.Mkdir(HOST_MAPPING_PATH, 0755) 
	}
	SetupFileLogger(OSPidLogFile, slog.LevelInfo)
	SetupFileLogger(GoPidLogFile, slog.LevelInfo)
	SetupFileLogger(LabelsMapLogFile, slog.LevelInfo)
	SetupFileLogger(ResolveLabelsLogFile, slog.LevelInfo)
}

func CloseAllFileLoggers() {
	for filePath, file := range fileHandlers {
		err := file.Close()
		if err != nil {
			slog.Error("Failed to close log file", "filePath", filePath, "error", err)
			continue
		}
		slog.Info("Closed log file", "filePath", filePath)
	}
}
