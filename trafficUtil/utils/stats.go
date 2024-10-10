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

	return mem
}
