//go:build windows

package main

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/utils"
	"golang.org/x/sys/windows/svc"
)

const serviceName = "AktoTrafficMirroring"

func platformMain(appMain func()) {
	isService, err := svc.IsWindowsService()
	if err != nil {
		log.Fatalf("could not detect if running as a windows service: %v", err)
	}
	if !isService {
		appMain()
		return
	}

	setupServiceLogging()
	scheduleRestart()
	go appMain()
	if err := svc.Run(serviceName, &aktoService{}); err != nil {
		log.Fatalf("windows service failed: %v", err)
	}
	os.Exit(0)
}

type aktoService struct{}

func (s *aktoService) Execute(args []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for req := range requests {
		switch req.Cmd {
		case svc.Interrogate:
			status <- req.CurrentStatus
		case svc.Stop, svc.Shutdown:
			log.Println("service stop requested")
			status <- svc.Status{State: svc.StopPending}
			return false, 0
		}
	}
	return false, 0
}

// scheduleRestart replaces the hourly restart run.sh does on linux. Exiting without reporting a
// stop is treated as a failure by the service manager, which restarts the service using the
// recovery actions set by install.ps1.
func scheduleRestart() {
	minutes := 60
	utils.InitVar("AKTO_RESTART_INTERVAL_MINUTES", &minutes)
	if minutes <= 0 {
		return
	}
	time.AfterFunc(time.Duration(minutes)*time.Minute, func() {
		log.Printf("restarting after %d minutes", minutes)
		os.Exit(1)
	})
}

func aktoDataDir() string {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return filepath.Join(programData, "Akto")
}

func collectorIdFilePath() string {
	dir := aktoDataDir()
	os.MkdirAll(dir, 0755)
	return filepath.Join(dir, "collector_id")
}

// setupServiceLogging sends stdout, stderr and the log package to a size capped file, since a
// service has no console. This matches what run.sh does with /tmp/dump.log on linux.
func setupServiceLogging() {
	dir := filepath.Join(aktoDataDir(), "logs")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, "mirroring.log"), os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	size, _ := f.Seek(0, io.SeekEnd)

	maxSize := 10 * 1024 * 1024
	utils.InitVar("MAX_LOG_SIZE", &maxSize)

	debug.SetCrashOutput(f, debug.CrashOptions{})

	r, w, err := os.Pipe()
	if err != nil {
		log.SetOutput(f)
		return
	}
	os.Stdout = w
	os.Stderr = w
	log.SetOutput(w)

	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				if size+int64(n) > int64(maxSize) {
					f.Truncate(0)
					f.Seek(0, io.SeekStart)
					size = 0
				}
				f.Write(buf[:n])
				size += int64(n)
			}
			if err != nil {
				return
			}
		}
	}()
}
