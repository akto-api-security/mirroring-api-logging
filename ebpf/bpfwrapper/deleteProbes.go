package bpfwrapper

import (
	"log/slog"
	"os/exec"
	"strings"

	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

func DeleteExistingAktoKernelProbes() {

	listCmd := exec.Command("perf", "probe", "-l")

	listOutput, err := listCmd.Output()
	if err != nil {
		slog.Error("Error listing kprobes", "error", err)
		return
	}

	// Split the output into lines
	kprobes := string(listOutput)
	kprobeLines := strings.Split(kprobes, "\n")

	// Iterate over kprobe lines and delete each kprobe
	for _, line := range kprobeLines {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			// Extract kprobe name
			kprobeName := fields[0]

			// skip non-akto probes
			if !strings.HasPrefix(kprobeName, "kprobes:akto") {
				continue
			}

			// Command to delete kprobe
			deleteCmd := exec.Command("perf", "probe", "-d", kprobeName)

			// Run the command
			if err := deleteCmd.Run(); err != nil {
				slog.Error("Error deleting kprobe", "kprobe", kprobeName, "error", err)
			} else {
				utils.PrintLog("Deleted kprobe", "kprobe", kprobeName)
			}
		}
	}
}
