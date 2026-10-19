package main

import (
	"encoding/json"
	"strconv"
	"testing"
)

func TestHeartbeatMessageFormat(t *testing.T) {
	prev := collectorId
	collectorId = "0b2c6f4e-1111-2222-3333-444455556666"
	t.Cleanup(func() { collectorId = prev })

	msg := buildHeartbeatMessage("akto-tc:test-pod", "aktosecurity/mirror-api-logging:k8s_agent")

	expected := map[string]string{
		"type":          "heartbeat",
		"daemonId":      "0b2c6f4e-1111-2222-3333-444455556666",
		"daemonPodName": "akto-tc:test-pod",
		"moduleType":    "TRAFFIC_COLLECTOR",
		"imageVersion":  "aktosecurity/mirror-api-logging:k8s_agent",
	}
	for k, v := range expected {
		if msg[k] != v {
			t.Errorf("%s: expected %q, got %q", k, v, msg[k])
		}
	}
	if _, err := strconv.ParseInt(msg["timestamp"], 10, 64); err != nil {
		t.Errorf("timestamp should be epoch seconds, got %q", msg["timestamp"])
	}

	var additionalData map[string]map[string]interface{}
	if err := json.Unmarshal([]byte(msg["additionalData"]), &additionalData); err != nil {
		t.Fatalf("additionalData is not a JSON object: %v", err)
	}
	for _, key := range []string{"memory_used_mb", "cpu_percent", "goroutines"} {
		if _, ok := additionalData["profiling"][key]; !ok {
			t.Errorf("profiling.%s missing", key)
		}
	}
}

func TestHeartbeatEnvOnlyAllowlistedKeys(t *testing.T) {
	t.Setenv("AKTO_TRAFFIC_BATCH_SIZE", "100")
	t.Setenv("AKTO_KAFKA_BROKER_MAL", "kafka:9092")
	t.Setenv("KAFKA_PASSWORD", "super-secret")
	t.Setenv("AKTO_MONGO_CONN", "mongodb://user:pass@host")

	env := getHeartbeatEnv()

	if env["AKTO_TRAFFIC_BATCH_SIZE"] != "100" || env["AKTO_KAFKA_BROKER_MAL"] != "kafka:9092" {
		t.Errorf("allowlisted keys missing: %v", env)
	}
	for _, secret := range []string{"KAFKA_PASSWORD", "AKTO_MONGO_CONN"} {
		if _, ok := env[secret]; ok {
			t.Errorf("%s must not be sent in heartbeats", secret)
		}
	}
}

func TestDaemonPodName(t *testing.T) {
	prev := collectorId
	collectorId = "abcdef12-0000-0000-0000-000000000000"
	t.Cleanup(func() { collectorId = prev })

	t.Setenv("AKTO_AGENT_NAME", "")
	t.Setenv("POD_NAME", "")
	t.Setenv("NODE_NAME", "")
	t.Setenv("HOSTNAME", "")
	if got := getDaemonPodName(); got != "akto-tc:daemon-abcdef12" {
		t.Errorf("fallback: got %q", got)
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

	t.Setenv("AKTO_AGENT_NAME", "siemens-ecs-collector")
	if got := getDaemonPodName(); got != "akto-tc:siemens-ecs-collector" {
		t.Errorf("agent name: got %q", got)
	}
}
