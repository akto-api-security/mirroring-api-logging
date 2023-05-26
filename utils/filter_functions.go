package utils

import "log"

func PassesFilter(filterHeaderValueMap map[string]string, reqHeaders map[string]string) bool {

	log.Println(reqHeaders)

	if filterHeaderValueMap == nil || len(filterHeaderValueMap) == 0 {
		return true
	}

	flag := true
	for k, v := range reqHeaders {
		filterVal, ok := filterHeaderValueMap[k]
		if ok {
			flag = flag && filterVal == v
		}
	}

	return flag
}
