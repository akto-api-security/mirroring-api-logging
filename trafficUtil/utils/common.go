package utils

import (
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

var printCounter = 500

func PrintLog(val string) {
	if printCounter > 0 {
		log.Println(val)
		printCounter--
	}
}

var IgnoreIpTraffic = false
var IgnoreCloudMetadataCalls = false

func InitIgnoreVars() {
	InitIgnoreVar("AKTO_IGNORE_IP_TRAFFIC", &IgnoreIpTraffic)
	InitIgnoreVar("AKTO_IGNORE_CLOUD_METADATA_CALLS", &IgnoreCloudMetadataCalls)
}

func InitIgnoreVar(envVarName string, targetVar interface{}) {
	envVar := os.Getenv(envVarName)
	if len(envVar) > 0 {
		switch v := targetVar.(type) {
		case *bool:
			*v = strings.ToLower(envVar) == "true"
			log.Printf("%s: %t\n", envVarName, *v)
		case *string:
			*v = envVar
			log.Printf("%s: %v\n", envVarName, *v)
		case *time.Duration:
			temp, err := time.ParseDuration(envVar + "s")
			if err == nil {
				*v = temp
				log.Printf("%s: %v\n", envVarName, *v)
			}
		case *int:
			temp, err := strconv.Atoi(envVar)
			if err == nil {
				*v = temp
				log.Printf("%s: %v\n", envVarName, *v)
			}
		default:
			log.Printf("Unsupported type for targetVar: %T\n", v)
		}
	} else {
		log.Printf("%s: missing. using default value\n", envVarName)
	}
}
