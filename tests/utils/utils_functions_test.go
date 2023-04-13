package utils

import (
	"github.com/akto-api-security/mirroring-api-logging/utils"
	"testing"
)

func TestCheckIfIpHost(t *testing.T) {
	host := "akto"
	res := utils.CheckIfIpHost(host)

	if res {
		t.Errorf("%s marked %t", host, res)
	}

	host = "akto2"
	res = utils.CheckIfIpHost(host)

	if res {
		t.Errorf("%s marked %t", host, res)
	}

	host = "1.1.1.1"
	res = utils.CheckIfIpHost(host)

	if !res {
		t.Errorf("%s marked %t", host, res)
	}

	host = "234234"
	res = utils.CheckIfIpHost(host)

	if !res {
		t.Errorf("%s marked %t", host, res)
	}
}
