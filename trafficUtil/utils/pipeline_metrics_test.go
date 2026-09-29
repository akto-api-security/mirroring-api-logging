package utils

import "testing"

func TestPipelineSnapshotCoverageAndReset(t *testing.T) {
	Pipeline.Reset()
	Pipeline.PairsAttempted.Store(4)
	Pipeline.PairsParseSuccess.Store(1)
	Pipeline.ConnsDroppedNotHTTP.Store(9)

	snap := Pipeline.Snapshot()
	if snap.PairsAttempted != 4 || snap.PairsParseSuccess != 1 || snap.ConnsDroppedNotHTTP != 9 {
		t.Fatalf("snapshot = %+v", snap)
	}
	if snap.CoveragePct != 25 {
		t.Fatalf("coverage = %v", snap.CoveragePct)
	}

	logged := Pipeline.SnapshotAndReset()
	if logged.PairsAttempted != 4 || logged.PairsParseSuccess != 1 || logged.ConnsDroppedNotHTTP != 9 || logged.CoveragePct != 25 {
		t.Fatalf("window = %+v", logged)
	}
	snap = Pipeline.Snapshot()
	if snap.PairsAttempted != 0 || snap.PairsParseSuccess != 0 || snap.ConnsDroppedNotHTTP != 0 || snap.CoveragePct != 0 {
		t.Fatalf("reset snapshot = %+v", snap)
	}
}
