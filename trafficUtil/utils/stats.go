package utils

import (
	"log"
	"os"
	"runtime"
)

var aktoMemThreshRestart = 500

func init() {
	InitVar("AKTO_MEM_THRESH_RESTART", &aktoMemThreshRestart)
}

func LogMemoryStats() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	if int(m.Alloc/1024/1024) > aktoMemThreshRestart {
		log.Println("current mem usage", m.Alloc/1024/1024)
		os.Exit(3)
	}

	log.Println("Alloc in MB: ", m.Alloc/1024/1024)
	log.Println("Sys in MB: ", m.Sys/1024/1024)
}
