package utils

import (
	"os"
	"strconv"
	"strings"
)

// HostMemoryMeminfo holds physical RAM figures from /proc/meminfo (Linux).
// Values are in mebibytes (1024-based), rounded from kernel kB lines.
// UsedMB is MemTotal − MemAvailable (MemFree fallback when MemAvailable is absent),
// matching the usual “used RAM” view and paralleling process memory_used_mb vs memory_total_mb.
type HostMemoryMeminfo struct {
	TotalMB float64
	UsedMB  float64
	OK      bool
}

// ReadHostMemoryMeminfo parses MemTotal and MemAvailable (MemFree fallback) from /proc/meminfo.
// On non-Linux or read/parse failure, returns OK=false and zeros.
func ReadHostMemoryMeminfo() HostMemoryMeminfo {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return HostMemoryMeminfo{}
	}
	var totalKB, availableKB, freeKB uint64
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		val, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			totalKB = val
		case "MemAvailable:":
			availableKB = val
		case "MemFree:":
			freeKB = val
		}
	}
	if totalKB == 0 {
		return HostMemoryMeminfo{}
	}
	avail := availableKB
	if avail == 0 {
		avail = freeKB
	}
	if avail > totalKB {
		avail = totalKB
	}
	usedKB := totalKB - avail
	totalMB := float64(totalKB) / 1024
	usedMB := float64(usedKB) / 1024
	return HostMemoryMeminfo{
		TotalMB: totalMB,
		UsedMB:  usedMB,
		OK:      true,
	}
}
