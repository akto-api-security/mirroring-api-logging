package utils

import (
	"log"

	trafficUtils "github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

var (
	ingestLogs  bool = false
	processLogs bool = false
)

func init() {
	trafficUtils.InitVar("INGEST_LOGS", &ingestLogs)
	trafficUtils.InitVar("PROCESS_LOGS", &processLogs)
}

func LogIngest(format string, args ...interface{}) {
	if ingestLogs {
		log.Printf(format, args...)
	}
}

func LogProcessing(format string, args ...interface{}) {
	if processLogs {
		log.Printf(format, args...)
	}
}
