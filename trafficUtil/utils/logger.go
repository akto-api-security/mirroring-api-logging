package utils

import (
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
)

func SetupLogger() {
	slog.Warn("Setting up logger")
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

	slog.Warn("Logger setup done with level", "level", level, "log level", aktoLogLevel)
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

type textLogger struct {
	handler      *os.File
	lastWriteTime int64
}

var fileHandlers = make(map[string]*textLogger)
const HOST_MAPPING_PATH = "/ebpf/logs/akto/"
const LOG_ROTATE_INTERVAL = 60 * 5 // 5 minutes

const (
	OSPidLogFile         = HOST_MAPPING_PATH + "ospidlog.txt"
	GoPidLogFile         = HOST_MAPPING_PATH + "gopidlog.txt"
	LabelsMapLogFile     = HOST_MAPPING_PATH + "labelsmaplog.txt"
	ResolveLabelsLogFile = HOST_MAPPING_PATH + "resolvelabels.txt"
)

func SetupFileLogger(filePath string) {
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		slog.Error("Failed to open log file", "filePath", filePath, "error", err)
		return
	}
	fileHandlers[filePath] = &textLogger{
		handler:      file,
		lastWriteTime: time.Now().Unix(),
	}
	slog.Warn("File logger setup done", "filePath", filePath)
}

func LogToSpecificFile(filePath string, message string, args ...any) {
	textLogger, exists := fileHandlers[filePath]
	if !exists {
		slog.Error("Logger not initialized for", "filePath", filePath)
		return
	}
	now := time.Now().Unix()
	if now-textLogger.lastWriteTime > LOG_ROTATE_INTERVAL {
		// empty the file contents
		if err := os.Truncate(filePath, 0); err != nil {
			slog.Error("Failed to truncate log file", "filePath", filePath, "error", err)
		}
		slog.Debug("Truncated log file due to rotation interval", "filePath", filePath)
	}
	textLogger.lastWriteTime = now 
	if _, err := textLogger.handler.WriteString(message); err != nil {
		slog.Error("Failed to write to log file", "filePath", filePath, "error", err)
		return
	}
}

func SetupAllFileLoggers() {
	if err := os.MkdirAll(HOST_MAPPING_PATH, 0755); err != nil {
		slog.Error("Failed to create log directory", "path", HOST_MAPPING_PATH, "error", err)
	}
	SetupFileLogger(OSPidLogFile)
	SetupFileLogger(GoPidLogFile)
	SetupFileLogger(LabelsMapLogFile)
	SetupFileLogger(ResolveLabelsLogFile)
}

// TODO: Call this somewhere in the shutdown process
func CloseAllFileLoggers() {
	for filePath, textLogger := range fileHandlers {
		err := textLogger.handler.Close()
		if err != nil {
			slog.Error("Failed to close log file", "filePath", filePath, "error", err)
			continue
		}
		slog.Info("Closed log file", "filePath", filePath)
	}
}