package utils

import (
	"math/rand"
	"testing"
)

// 1. New seqs count once; immediate repeats don't. Zero value is usable directly.
func TestSeqRing_SequentialCountOnce(t *testing.T) {
	var b SeqRingBitset
	const n = 5000
	for i := uint32(1); i <= n; i++ {
		if !b.MarkNew(i) {
			t.Fatalf("seq %d: first sighting should be new", i)
		}
	}
	for i := uint32(1); i <= n; i++ {
		if b.MarkNew(i) {
			t.Fatalf("seq %d: repeat should not be new", i)
		}
	}
}

// 2. Out-of-order arrivals inside the window are each counted once and deduped.
func TestSeqRing_OutOfOrderWithinWindow(t *testing.T) {
	var b SeqRingBitset
	order := []uint32{5, 3, 8, 1, 7, 2, 6, 4}
	for _, s := range order {
		if !b.MarkNew(s) {
			t.Fatalf("seq %d: first (out-of-order) sighting should be new", s)
		}
	}
	for _, s := range order {
		if b.MarkNew(s) {
			t.Fatalf("seq %d: repeat should not be new", s)
		}
	}
}

// 3. A frontier jump must reset the slots it swept over, so a later in-window
//    arrival of a skipped seq is still counted (its stale bit was cleared).
func TestSeqRing_GapAdvanceClearsSkipped(t *testing.T) {
	var b SeqRingBitset
	if !b.MarkNew(10) {
		t.Fatal("seq 10 should be new")
	}
	if !b.MarkNew(1000) { // jump: sweeps 11..1000
		t.Fatal("seq 1000 should be new")
	}
	if !b.MarkNew(500) { // skipped-but-in-window -> must be new
		t.Fatal("in-window skipped seq 500 should be new")
	}
	if b.MarkNew(500) {
		t.Fatal("seq 500 repeat should not be new")
	}
}

// 3b. The core protection: a seq is counted, the frontier advances well past it
//     (but stays within the window), then the SAME seq re-arrives as a late chunk
//     (its group was flushed/deleted and re-created). MarkNew must return false so
//     GroupsCreated is not double-counted. This is why seenMsgSeqs exists.
func TestSeqRing_LateReArrivalWithinWindow(t *testing.T) {
	var b SeqRingBitset
	if !b.MarkNew(100) {
		t.Fatal("seq 100 first sighting should be new")
	}
	// Frontier advances by a realistic late-arrival distance, still << SeqWindow.
	for s := uint32(101); s <= 700; s++ {
		b.MarkNew(s)
	}
	// seq 100 re-arrives late while still inside the window.
	if b.MarkNew(100) {
		t.Fatal("late re-arrival of already-counted seq 100 must not count again")
	}
	// Sanity: an unseen seq behind the frontier (50 < 700, never marked) is new.
	if !b.MarkNew(50) {
		t.Fatal("unseen in-window seq behind the frontier should still be new")
	}
}

// 4. seq S and S+SeqWindow map to the same bit. Off-by-one at the window edge:
//    S+SeqWindow-1 is still inside the window (S not yet evicted); S+SeqWindow
//    evicts S and reuses its bit, so it must read as new.
func TestSeqRing_WrapAroundBoundary(t *testing.T) {
	var b SeqRingBitset
	const s = uint32(7)
	b.MarkNew(s)

	// Advancing to the last in-window seq must not disturb s's bit.
	b.MarkNew(s + SeqWindow - 1)
	if b.MarkNew(s) {
		t.Fatal("seq s still inside window should not read as new")
	}

	// Crossing exactly one window evicts s; its shared bit is reused.
	var c SeqRingBitset
	c.MarkNew(s)
	if !c.MarkNew(s + SeqWindow) {
		t.Fatal("seq s+SeqWindow should be new (wraps onto s's bit after eviction)")
	}
}

// 5. Documented residual: an arrival more than SeqWindow behind the frontier has
//    been evicted, so it is (incorrectly, but acceptably) treated as new again.
func TestSeqRing_BeyondWindowResidual(t *testing.T) {
	var b SeqRingBitset
	b.MarkNew(1)
	b.MarkNew(1 + SeqWindow + 100) // frontier jumps well past the window
	if !b.MarkNew(1) {
		t.Fatal("seq 1 evicted by >window jump is expected to look new again")
	}
}

// 6. Oracle: for any stream whose reorder distance stays under SeqWindow, MarkNew
//    must match an exact "seen this before" map on every decision.
func TestSeqRing_MatchesMapOracle(t *testing.T) {
	var b SeqRingBitset
	seen := make(map[uint32]bool)
	rng := rand.New(rand.NewSource(1))

	frontier := uint32(1)
	for i := 0; i < 200000; i++ {
		// Emit a seq near the frontier: mostly advancing, sometimes a small
		// backward jitter (reorder), always within SeqWindow of the frontier.
		var seq uint32
		if rng.Intn(4) == 0 && frontier > 200 {
			seq = frontier - uint32(rng.Intn(200)) // reorder up to 200 back
		} else {
			frontier += uint32(rng.Intn(3)) // 0..2 forward
			seq = frontier
		}
		if seq == 0 {
			seq = 1
		}
		got := b.MarkNew(seq)
		want := !seen[seq]
		seen[seq] = true
		if got != want {
			t.Fatalf("i=%d seq=%d frontier=%d: MarkNew=%v want=%v", i, seq, frontier, got, want)
		}
	}
}

// MarkNew must not allocate on the hot path.
func TestSeqRing_NoAlloc(t *testing.T) {
	var b SeqRingBitset
	seq := uint32(0)
	allocs := testing.AllocsPerRun(1000, func() {
		seq++
		b.MarkNew(seq)
	})
	if allocs != 0 {
		t.Fatalf("MarkNew allocated %v/op, want 0", allocs)
	}
}
