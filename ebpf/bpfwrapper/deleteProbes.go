package bpfwrapper

import (
	"fmt"
	"os/exec"
	"strings"
)

func DeleteExistingAktoKernelProbes() {

	listCmd := exec.Command("perf", "probe", "-l")

	listOutput, err := listCmd.Output()
	if err != nil {
		fmt.Println("Error listing kprobes:", err)
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
				fmt.Printf("Error deleting kprobe %s: %v\n", kprobeName, err)
			} else {
				fmt.Printf("Deleted kprobe %s\n", kprobeName)
			}
		}
	}
}
