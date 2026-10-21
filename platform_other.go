//go:build !windows

package main

import "syscall"

func platformMain(appMain func()) {
	appMain()
}

// processCPUSeconds is the user plus system CPU time this process has used
func processCPUSeconds() float64 {
	var rusage syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &rusage)
	return float64(rusage.Utime.Sec+rusage.Stime.Sec) +
		float64(rusage.Utime.Usec+rusage.Stime.Usec)/1000000
}

func collectorIdFilePath() string {
	return "/collector_id_file"
}
