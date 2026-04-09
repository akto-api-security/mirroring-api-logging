package utils

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

var DebugStrings = []string{}

func init() {
	debugStringsEnv := ""
	InitVar("DEBUG_URLS", &debugStringsEnv)
	if len(debugStringsEnv) > 0 {
		DebugStrings = strings.Split(debugStringsEnv, ",")
	}
	slog.Info("debugStrings", "DebugStrings", DebugStrings)

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			UpdateDebugStringsFromFile()
			<-ticker.C
		}
	}()
}

func InitVar(envVarName string, targetVar interface{}) {
	envVar := os.Getenv(envVarName)
	if len(envVar) > 0 {
		switch v := targetVar.(type) {
		case *bool:
			*v = strings.ToLower(envVar) == "true"
			slog.Warn("Setting env value", "name", envVarName, "value", *v)
		case *string:
			*v = envVar
			slog.Warn("Setting env value", "name", envVarName, "value", *v)
		case *time.Duration:
			temp, err := time.ParseDuration(envVar + "s")
			if err == nil {
				*v = temp
				slog.Warn("Setting env value", "name", envVarName, "value", *v)
			}
		case *int:
			temp, err := strconv.Atoi(envVar)
			if err == nil {
				*v = temp
				slog.Warn("Setting env value", "name", envVarName, "value", *v)
			}
		default:
			slog.Warn("Unsupported type for targetVar", "type", v)
		}
	} else {
		slog.Warn("Missing env value, using default value", "name", envVarName)
	}
}

// Reads /ebpf/debug-urls.txt and updates DebugStrings with any new URLs found in the file (one per line)
func UpdateDebugStringsFromFile() {
	filePath := "/app/debug-urls.txt"
	f, err := os.Open(filePath)
	if err != nil {
		// File may not exist, that's fine
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	fileUrls := []string{}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			fileUrls = append(fileUrls, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return
	}

	if len(fileUrls) > 0 {
		// Merge with env DebugStrings, avoid duplicates
		urlSet := make(map[string]struct{})
		for _, u := range DebugStrings {
			urlSet[u] = struct{}{}
		}
		newUrls := []string{}
		for _, u := range fileUrls {
			if _, exists := urlSet[u]; !exists {
				newUrls = append(newUrls, u)
			}
			urlSet[u] = struct{}{}
		}
		if len(newUrls) > 0 {
			merged := make([]string, 0, len(urlSet))
			for u := range urlSet {
				merged = append(merged, u)
			}
			DebugStrings = merged
			slog.Info("New debugStrings found in file", "newUrls", newUrls, "DebugStrings", DebugStrings)
		}
	}
}

func CheckIfIpHost(host string) bool {
	return strings.ToLower(host) == strings.ToUpper(host)
}


func CheckDebugUrlAndPrint(url string, host string, message string) {
	// url or host. [array string]
	if len(DebugStrings) > 0 {
		for _, debugString := range DebugStrings {
			if strings.Contains(url, debugString) {
				logMsg := fmt.Sprintf("url: %s, host: %s, message: %s", url, host, message)
				slog.Warn(logMsg)
				break
			} else if strings.Contains(host, debugString) {
				logMsg := fmt.Sprintf("url: %s, host: %s, message: %s", url, host, message)
				slog.Warn(logMsg)
				break
			}
		}
	}
}