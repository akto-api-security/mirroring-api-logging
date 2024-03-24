package utils

import (
	"regexp"
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

var trafficFilters = GetFilter()

func FilterPacket(headers map[string]string) bool {

	skip := false

	for _, filter := range trafficFilters {

		if len(filter.Key.Eq) > 0 {
			r, err := regexp.Compile(filter.Value.Regex)

			if err != nil {
				r, _ = regexp.Compile(".*")
			}

			headerKey := ""
			headerValue := ""

			for tempKey, tempValue := range headers {
				if strings.EqualFold(tempKey, filter.Key.Eq) {
					headerKey = tempKey
					headerValue = tempValue
					break
				}
			}

			if headerKey == "" && strings.EqualFold(filter.Key.IfAbsent, "reject") {
				skip = true
			} else if headerKey != "" && !r.MatchString(headerValue) {
				skip = true
			}
		}

	}

	return skip
}
