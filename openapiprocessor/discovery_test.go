package openapiprocessor

import (
	"testing"
	"time"
)

func TestShouldSendSpecHardRefresh(t *testing.T) {
	roleArn, apiID, stage := "role-hard-refresh", "api1", "prod"
	spec := []byte(`{"openapi":"3.0.1"}`)

	if !shouldSendSpec(roleArn, apiID, stage, spec) {
		t.Fatal("new spec should be sent")
	}
	if shouldSendSpec(roleArn, apiID, stage, spec) {
		t.Fatal("unchanged spec should be skipped before hard refresh is due")
	}

	// Pretend the last upload happened just over the refresh window ago
	key := roleArn + "|" + apiID + "|" + stage
	GetTracker().discoveredAPIs[key].LastSent = time.Now().Add(-SPEC_HARD_REFRESH_AFTER - time.Minute).Unix()

	if !shouldSendSpec(roleArn, apiID, stage, spec) {
		t.Fatal("unchanged spec should be resent once hard refresh is due")
	}
	if shouldSendSpec(roleArn, apiID, stage, spec) {
		t.Fatal("refresh window should restart after a hard refresh")
	}
	if !shouldSendSpec(roleArn, apiID, stage, []byte(`{"openapi":"3.0.2"}`)) {
		t.Fatal("changed spec should be sent")
	}
}
