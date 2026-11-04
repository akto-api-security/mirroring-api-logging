package main

import (
	"testing"
)

func TestTrafficDisableEgressDefaultOn(t *testing.T) {
	t.Setenv("TRAFFIC_DISABLE_EGRESS", "")
	if !trafficDisableEgress() {
		t.Fatal("TRAFFIC_DISABLE_EGRESS must default on so connect() sockets are not captured")
	}
}

func TestTrafficDisableEgressCanBeTurnedOff(t *testing.T) {
	t.Setenv("TRAFFIC_DISABLE_EGRESS", "false")
	if trafficDisableEgress() {
		t.Fatal("TRAFFIC_DISABLE_EGRESS=false should capture connect() sockets")
	}
}
