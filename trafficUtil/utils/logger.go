package utils

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const LevelOff = slog.Level(99)

var (
	ingestLogs         bool = false
	processLogs        bool = false
	aktoLogLevel       string
	level              slog.Level = slog.LevelWarn
	FileLoggingEnabled bool       = false
)

func SetupLogger() {
	slog.Warn("Setting up logger")
	InitVar("INGEST_LOGS", &ingestLogs)
	InitVar("PROCESS_LOGS", &processLogs)
	InitVar("AKTO_LOG_LEVEL", &aktoLogLevel)
	InitVar("AKTO_FILE_LOGGING_ENABLED", &FileLoggingEnabled)

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

func LogLevel() slog.Level     { return level }
func IngestLogsEnabled() bool  { return ingestLogs }
func ProcessLogsEnabled() bool { return processLogs }

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
	handler       *os.File
	lastWriteTime int64
}

var fileHandlers = make(map[string]*textLogger)

const LOG_ROTATE_INTERVAL = 60 * 5 // 5 minutes

func ebpfAktoLogDir() string {
	return filepath.Join(EbpfRootDir, "logs", "akto")
}

func GoPidLogFilePath() string {
	return filepath.Join(ebpfAktoLogDir(), "gopidlog.txt")
}

func LabelsMapLogFilePath() string {
	return filepath.Join(ebpfAktoLogDir(), "labelsmaplog.txt")
}

func SetupFileLogger(filePath string) {
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		slog.Error("Failed to open log file", "filePath", filePath, "error", err)
		return
	}
	fileHandlers[filePath] = &textLogger{
		handler:       file,
		lastWriteTime: time.Now().Unix(),
	}
	slog.Warn("File logger setup done", "filePath", filePath)
}

func LogToSpecificFile(filePath string, message string, args ...any) {
	if !FileLoggingEnabled {
		slog.Warn("File logging is disabled, skipping log to file", "filePath", filePath)
		return
	}

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
	if !FileLoggingEnabled {
		slog.Warn("File logging is disabled, skipping setup")
		return
	}
	if err := os.MkdirAll(ebpfAktoLogDir(), 0755); err != nil {
		slog.Error("Failed to create log directory", "path", ebpfAktoLogDir(), "error", err)
	}
	SetupFileLogger(GoPidLogFilePath())
	SetupFileLogger(LabelsMapLogFilePath())
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
