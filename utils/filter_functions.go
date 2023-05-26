package utils

import (
	"log"
	"strings"
)

func PassesFilter(filterHeaderValueMap map[string]string, reqHeaders map[string]string) bool {

	log.Println(reqHeaders)

	if filterHeaderValueMap == nil || len(filterHeaderValueMap) == 0 {
		return true
	}

	flag := true
	for filterKey, filterVal := range filterHeaderValueMap {
		filterKeyLower := strings.ToLower(filterKey)
		filterValLower := strings.ToLower(filterVal)

		headerVal, ok := reqHeaders[filterKeyLower]
		if ok {
			flag = flag && filterValLower == headerVal
		} else {
			flag = false
		}
	}

	return flag
}
