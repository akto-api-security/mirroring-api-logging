package kafkaUtil

import "testing"

func TestCountDebugPair(t *testing.T) {
	g0, b0 := goodRequests.Load(), badRequests.Load()
	countDebugPair("tok-1", "tok-1", "", TrafficContext{}, nil)            // echoed in a header
	countDebugPair("tok-2", "", `{"echo":"tok-2"}`, TrafficContext{}, nil) // echoed in the body
	countDebugPair("tok-3", "tok-4", "nothing", TrafficContext{}, nil)     // another exchange's response
	if g, b := goodRequests.Load()-g0, badRequests.Load()-b0; g != 2 || b != 1 {
		t.Fatalf("good=%d bad=%d, want 2 and 1", g, b)
	}
}
