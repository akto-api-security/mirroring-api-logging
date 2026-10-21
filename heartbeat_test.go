package main

import "testing"

func TestDaemonPodName(t *testing.T) {
	t.Setenv("AKTO_AGENT_NAME", "")
	t.Setenv("POD_NAME", "")
	t.Setenv("NODE_NAME", "")
	t.Setenv("HOSTNAME", "")
	if got, want := getDaemonPodName(), "akto-tc:daemon-"+uniqueDaemonsetId[:8]; got != want {
		t.Errorf("fallback: got %q, want %q", got, want)
	}

	t.Setenv("HOSTNAME", "ip-10-0-1-5")
	if got := getDaemonPodName(); got != "akto-tc:ip-10-0-1-5" {
		t.Errorf("hostname: got %q", got)
	}

	t.Setenv("POD_NAME", "collector-7f9")
	t.Setenv("NODE_NAME", "node-1")
	if got := getDaemonPodName(); got != "akto-tc:collector-7f9:node-1" {
		t.Errorf("pod/node: got %q", got)
	}

	t.Setenv("AKTO_AGENT_NAME", "ecs-collector")
	if got := getDaemonPodName(); got != "akto-tc:ecs-collector" {
		t.Errorf("agent name: got %q", got)
	}
}

func TestImageVersionComesFromBuild(t *testing.T) {
	prev := aktoImageVersion
	aktoImageVersion = "aktosecurity/mirror-api-logging:k8s_agent"
	t.Cleanup(func() { aktoImageVersion = prev })

	if got := getImageVersion(); got != "aktosecurity/mirror-api-logging:k8s_agent" {
		t.Errorf("got %q", got)
	}
}

func TestProfilingDataFields(t *testing.T) {
	profiling := getProfilingData()
	for _, key := range []string{"memory_used_mb", "memory_total_mb", "memory_cumulative_mb", "cpu_percent", "cpu_cores_used", "cpu_cores_total", "goroutines", "num_gc"} {
		if _, ok := profiling[key]; !ok {
			t.Errorf("profiling.%s missing", key)
		}
	}
}
