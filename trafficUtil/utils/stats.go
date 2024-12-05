package utils

import (
	"log"
	"os"
	"runtime"
)

var aktoMemThreshRestart = 500

func init() {
	InitVar("AKTO_MEM_THRESH_RESTART", &aktoMemThreshRestart)
	InitVar("AKTO_MEM_HARD_LIMIT", &aktoMemThreshRestart)
}

func LogMemoryStats() int {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	mem := int(m.Alloc / 1024 / 1024)
	if mem > aktoMemThreshRestart {
		log.Println("current mem usage", mem)
		os.Exit(3)
	}

	log.Println("Alloc in MB: ", mem)
	log.Println("Sys in MB: ", m.Sys/1024/1024)

	// gc stats

	log.Println("Last gc finished: ", m.LastGC)
	log.Println("Target heap size of next gc cycle: ", m.NextGC)
	log.Println("Stop The world pauses ", m.PauseTotalNs)
	log.Println("GcSys ", m.GCSys)
	log.Println("GCCPUFraction ", m.GCCPUFraction)
	log.Println("NumGC ", m.NumGC)
	log.Println("NumForcedGC ", m.NumForcedGC)

	return mem
}
