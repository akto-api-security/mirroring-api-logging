package utils

// SeqRingBitset is a fixed-size, allocation-free "have I seen this seq before?"
// set for a stream of near-monotonic uint32 sequence numbers (e.g. msg_seq).
//
// It is a ring of SeqWindow bits (one bit per seq, indexed by seq % SeqWindow),
// stored inline as a [SeqWindow/64]uint64 array — so the ZERO VALUE is ready to
// use, no constructor and no make():
//
//	var seen utils.SeqRingBitset   // ready
//	if seen.MarkNew(msgSeq) { groupsCreated++ }
//
// Why a ring instead of a map: a map keyed by every seq ever seen grows without
// bound for the life of a connection. A ring keeps only the most-recent
// SeqWindow seqs and evicts older ones automatically, giving CONSTANT memory
// (SeqWindow/8 bytes) and zero churn after the first use.
//
// Correctness within the window: seq S and seq S-SeqWindow map to the same bit.
// As the frontier (highest seq seen) advances, MarkNew clears the bit of the seq
// falling out of the window BEFORE the entering seq reuses it, so a stale bit can
// never be mistaken for a real "seen". This makes MarkNew exact for any arrival
// whose distance behind the frontier is < SeqWindow — which covers all realistic
// out-of-order and late arrivals (observed reorder is in the hundreds; the window
// is 65536, ~100x margin).
//
// Residual (accepted): an arrival more than SeqWindow behind the frontier has had
// its bit evicted, so MarkNew would treat it as new again (double count). With
// SeqWindow=65536 this effectively never happens.
//
// Worked example with a tiny window (SeqWindow=8, bit = seq%8):
//
//	seq:  1 2 3 4 5 6 7 8 9 ...
//	bit:  1 2 3 4 5 6 7 0 1   <- seq 9 and seq 1 share bit 1
//
//	MarkNew(1) -> sets bit 1, returns true  (new)
//	...frontier advances to 9; entering seq 9 reuses bit 1, so its stale
//	   occupant (seq 1) is cleared first...
//	MarkNew(9) -> bit 1 was cleared, sets it, returns true (correctly new)
//	MarkNew(1) again, while still within window -> bit 1 still set -> false (not recounted)
//
// Not safe for concurrent use; guard with the caller's lock (Tracker holds one).
type SeqRingBitset struct {
	bits [SeqWindow / 64]uint64
	// high is the highest seq passed to MarkNew so far, +1 (0 means "nothing yet").
	// Stored as +1 so the zero value correctly means "empty".
	highPlus1 uint32
}

// SeqWindow is the number of seqs the ring remembers. Must be a power of two so
// seq%SeqWindow reduces to a mask. 65536 bits = 1024 uint64 = 8 KB per bitset.
const SeqWindow = 65536

// MarkNew records seq and reports whether this is the first time seq has been
// seen within the current window. Returns true exactly once per new seq (use it
// to increment a "unique seqs" counter); returns false for a repeat/late arrival
// of a seq still inside the window.
func (b *SeqRingBitset) MarkNew(seq uint32) bool {
	// Advance the frontier and evict slots for any seqs that just fell out of
	// the window, so their stale bits don't masquerade as "seen".
	if b.highPlus1 == 0 {
		b.highPlus1 = seq + 1
	} else if h := b.highPlus1 - 1; seq > h {
		// Frontier moves from h to seq. Every index in (h, seq] is now entering
		// the window and its previous occupant (index - SeqWindow) is leaving —
		// same bit position — so clear it. Cap the sweep at SeqWindow: advancing
		// by more than a full window clears everything.
		n := seq - h
		if n > SeqWindow {
			n = SeqWindow
		}
		for s := seq - n + 1; ; s++ {
			b.clear(s)
			if s == seq {
				break
			}
		}
		b.highPlus1 = seq + 1
	}

	if b.test(seq) {
		return false
	}
	b.set(seq)
	return true
}

func (b *SeqRingBitset) idx(seq uint32) (word uint32, mask uint64) {
	i := seq & (SeqWindow - 1) // seq % SeqWindow (power-of-two)
	return i >> 6, uint64(1) << (i & 63)
}

func (b *SeqRingBitset) test(seq uint32) bool { w, m := b.idx(seq); return b.bits[w]&m != 0 }
func (b *SeqRingBitset) set(seq uint32)       { w, m := b.idx(seq); b.bits[w] |= m }
func (b *SeqRingBitset) clear(seq uint32)     { w, m := b.idx(seq); b.bits[w] &^= m }
