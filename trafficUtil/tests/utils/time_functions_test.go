package utils

import (
	"testing"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

func TestEpochDays(t *testing.T) {
	d, u := utils.EpochDays()
	now := int(time.Now().Unix())

	d1 := d * 24 * 60 * 60
	u1 := u * 24 * 60 * 60

	if (u1 - d1) != 24*60*60 {
		t.Errorf("wrong difference: %d", (u1 - d1))
	}

	if d1 > now || u1 < now {
		t.Errorf("now(%d) not coming between u1 (%d) and d1(%d)", now, u1, d1)
	}
}

func TestEpochHours(t *testing.T) {
	d, u := utils.EpochHours()
	now := int(time.Now().Unix())

	d1 := d * 60 * 60
	u1 := u * 60 * 60

	if (u1 - d1) != 60*60 {
		t.Errorf("wrong difference: %d", (u1 - d1))
	}

	if d1 > now || u1 < now {
		t.Errorf("now(%d) not coming between u1 (%d) and d1(%d)", now, u1, d1)
	}
}
