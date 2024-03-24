package utils

import (
	"log"
	"os"
	"runtime"
	"strconv"
)

var aktoMemThreshRestart = 500

func InitMemThresh() {
	aktoMemThresh := os.Getenv("AKTO_MEM_THRESH_RESTART")
	if len(aktoMemThresh) > 0 {
		aktoMemThreshRestartLocal, err := strconv.Atoi(aktoMemThresh)
		if err != nil {
			log.Println("AKTO_MEM_THRESH_RESTART should be valid integer. Found ", aktoMemThresh)
			return
		} else {
			log.Println("Setting akto mem threshold threshold at " + strconv.Itoa(aktoMemThreshRestartLocal))
		}
		aktoMemThreshRestart = aktoMemThreshRestartLocal
	}
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
