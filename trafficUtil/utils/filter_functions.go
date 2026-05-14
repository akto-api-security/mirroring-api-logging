package utils

import (
	"regexp"
	"strings"
)

type compiledFilterObject struct {
	filter FilterObject
	regex  *regexp.Regexp
}

func PassesFilter(filterHeaderValueMap map[string]string, reqHeaders map[string]string) bool {

	if len(filterHeaderValueMap) == 0 {
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

var trafficFilters = compileFilters(GetFilter())

func compileFilters(filters []FilterObject) []compiledFilterObject {
	compiled := make([]compiledFilterObject, 0, len(filters))
	for _, filter := range filters {
		r, err := regexp.Compile(filter.Value.Regex)
		if err != nil {
			r = regexp.MustCompile(".*")
		}
		compiled = append(compiled, compiledFilterObject{
			filter: filter,
			regex:  r,
		})
	}
	return compiled
}

func FilterPacket(headers map[string]string) bool {

	skip := false

	for _, filter := range trafficFilters {

		if len(filter.filter.Key.Eq) > 0 {
			headerKey := ""
			headerValue := ""

			for tempKey, tempValue := range headers {
				if strings.EqualFold(tempKey, filter.filter.Key.Eq) {
					headerKey = tempKey
					headerValue = tempValue
					break
				}
			}

			if headerKey == "" && strings.EqualFold(filter.filter.Key.IfAbsent, "reject") {
				skip = true
			} else if headerKey != "" && !filter.regex.MatchString(headerValue) {
				skip = true
			}
		}

	}

	return skip
}
