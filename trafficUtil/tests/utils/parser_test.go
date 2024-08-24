package utils

import (
	"testing"

	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/kafkaUtil"
)

func TestMethodCheck(t *testing.T) {
	testMethod("get", true, t)
	testMethod("gget", false, t)
	testMethod("GET", true, t)
	testMethod("GGET", false, t)
	testMethod("POST", true, t)
	testMethod("other", false, t)
}

func testMethod(method string, check bool, t *testing.T) {
	isValid := kafkaUtil.IsValidMethod(method)
	if isValid != check {
		t.Errorf("%s marked %t", method, isValid)
	}
}
