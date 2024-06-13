package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

var memoryLimit = 400

func init() {
	utils.InitVar("AKTO_MEM_SOFT_LIMIT_2", &memoryLimit)
	memoryLimit = memoryLimit * 1024 * 1024
}

func calculateMemory(pid int) (uint64, error) {

	f, err := os.Open(fmt.Sprintf("/host/proc/%d/smaps", pid))
	if err != nil {
		return 0, err
	}
	defer f.Close()

	res := uint64(0)
	pfx := []byte("Pss:")
	r := bufio.NewScanner(f)
	for r.Scan() {
		line := r.Bytes()
		if bytes.HasPrefix(line, pfx) {
			var size uint64
			_, err := fmt.Sscanf(string(line[4:]), "%d", &size)
			if err != nil {
				return 0, err
			}
			res += size
		}
	}
	if err := r.Err(); err != nil {
		return 0, err
	}

	return res, nil
}

func monitorMemory(pid int) bool {
	for {
		memUsage, err := calculateMemory(pid)
		fmt.Printf("Mem usage: %v err: %v\n", memUsage, err)
		if memUsage > uint64(memoryLimit) {
			return true
		}

		if _, err := os.FindProcess(pid); err != nil {
			fmt.Println("Process has exited.")
			return false
		}

		time.Sleep(1 * time.Second) // Check every second
	}
}

func main() {

	for {
		cmd := exec.Command("./ebpf-logging")

		stdout, err := cmd.StdoutPipe()
		if err != nil {
			fmt.Printf("stdout error: %v\n", stdout)
		}

		stderr, err := cmd.StderrPipe()
		if err != nil {
			fmt.Printf("stderr error: %v\n", stdout)
		}

		if err := cmd.Start(); err != nil {
			fmt.Println("Error starting process:", err)
			return
		}
		pid := cmd.Process.Pid
		fmt.Println("Started process PID:", pid)

		go func() {
			in := bufio.NewScanner(stdout)
			for in.Scan() {
				fmt.Println(in.Text())
			}
			if err := in.Err(); err != nil {
				fmt.Printf("error in stdout: %s\n", err)
				return
			}
		}()

		go func() {
			in := bufio.NewScanner(stderr)
			for in.Scan() {
				fmt.Println(in.Text())
			}
			if err := in.Err(); err != nil {
				fmt.Printf("error in stderr: %s\n", err)
				return
			}
		}()

		overLimit := monitorMemory(pid)

		if overLimit {
			fmt.Println("Memory limit exceeded, killing process...")
			if err := cmd.Process.Kill(); err != nil {
				fmt.Println("Failed to kill process:", err)
				return
			}
			fmt.Println("Process killed. Restarting...")
		} else {
			fmt.Println("Process exited without exceeding memory limit.")
			return
		}
		time.Sleep(10 * time.Second) // sleep for 10 second before restarting
	}
}
