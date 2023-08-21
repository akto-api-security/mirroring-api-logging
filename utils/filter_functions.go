package utils

import (
	"strings"
)

func PassesFilter(filterHeaderValueMap map[string]string, reqHeaders map[string]string) bool {

	if filterHeaderValueMap == nil || len(filterHeaderValueMap) == 0 {
		return true
	}

	flag := false
	for filterKey, filterVal := range filterHeaderValueMap {
		headerVal, ok := reqHeaders[filterKey]
		if ok {
			flag = flag || strings.EqualFold(filterVal, headerVal)
		}

		if flag {
			return flag
		}
	}

	return flag
}
