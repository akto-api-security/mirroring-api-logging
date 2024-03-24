package utils

import (
	"log"
)

const (
	LogLevelDebug = iota
	LogLevelInfo
	LogLevelWarning
	LogLevelError
)

var logLevel = LogLevelInfo // Set default log level

func SetLogLevel(level int) {
	logLevel = level
}

func Debugf(format string, args ...interface{}) {
	if logLevel <= LogLevelDebug {
		log.Printf(format, args...)
	}
}

func Infof(format string, args ...interface{}) {
	if logLevel <= LogLevelInfo {
		log.Printf(format, args...)
	}
}

func Warningf(format string, args ...interface{}) {
	if logLevel <= LogLevelWarning {
		log.Printf(format, args...)
	}
}

func Errorf(format string, args ...interface{}) {
	if logLevel <= LogLevelError {
		log.Printf(format, args...)
	}
}
