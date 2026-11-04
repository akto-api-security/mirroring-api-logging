package connections

import "testing"

func TestDisableEgressDefaultOn(t *testing.T) {
	if !disableEgress {
		t.Fatal("TRAFFIC_DISABLE_EGRESS must default on; kernel skip and parse skip share this flag")
	}
}
