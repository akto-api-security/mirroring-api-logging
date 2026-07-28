# Rate-sweep capacity results — `TestRateSweep`

Measured pipeline capacity for the eBPF collector's ingest + worker + flush (+ parse)
path, via the `TestRateSweep` harness in `callback_ratesweep_test.go`.

## What this measures

A producer paced to a fixed events/sec feeds a bounded channel; the **real**
`SocketDataEventCallback` drains it into the **real** per-connection worker → flush
→ (parse) path. We find the rate at which the pipeline stops keeping up.

```
producer (rate R, non-blocking send) → eventChan(cap=100000)
     → SocketDataEventCallback (real) → SendDataEvent → per-conn worker
     → flush routine (500ms) → ProcessSinglePair → parse (KafkaDisabled: no produce)
```

Columns in the tables below:
- `offered/s` — events the producer actually pushed (falls below the target rate when saturated).
- `consumed/s` — sustained drain rate at window end = **the capacity number**.
- `GiB/s` — throughput of what got through = `consumed/s × 4502 ÷ 2³⁰`.
- `kernelDrop` — `eventChan` full: callback couldn't drain (kernel-ring-drop analog). Shown as `count (pct)`.
- `perConnDrop` — per-conn channel full: worker/flush/parse couldn't drain. `count (pct)`.
- `cov%` — eventual coverage after a quiescence drain (parse-on only; parse-off = `—` by design).

Drop `count = offered × pct` (the harness reports the pct; count is derived).

Fixture/config: payload **4 KB** (`reqBytes=4434`, `respBytes=4435`, **events/pair=2**, wire
bytes/event = 68 attr + chunk ≈ **4502 B**), `rsConns=300`, `rsWindow=5s`, `chanCap=100000`,
`PerConnChBufferSize=200`, `inactivityThreshold=1s`. Box: 8 CPUs.

## How to reproduce

```bash
cd /Users/mann/workspace/mirroring-api-logging-2/ebpf

# flags MUST come after `-args`, else `go test` mis-parses the package path and
# tries to build the bcc root pkg (fails on macOS: linux/bpf.h not found).
AKTO_MEM_THRESH_RESTART=12000 AKTO_SYS_MEM_HARD_LIMIT=14000 \
  go test -run TestRateSweep -v -count=1 -timeout 400s ./connections/ \
  -args -parse=off -gomaxprocs=2 \
  2>&1 | grep -vE "level=(WARN|INFO)|logger.go|Setting up|Logger setup|File logging"
```

- `-parse=on|off|both` selects the arm; `-gomaxprocs=N` sets cores.
- `-count=1` forces a fresh run (perf test; never trust the result cache).
- Each sweep ≈ 50–80s. Fixtures load from `../../testdata/`.
- Run parse-off as separate fresh processes (not `-count=3`): it doesn't drain
  pairs, so memory grows with rate — the raised mem thresholds keep the watchdog
  from `os.Exit`-ing mid-sweep, and a fresh process resets memory between runs.

---

## GOMAXPROCS=2 · parse-off  (ingest + tracker store only)

| rate/s | run | offered/s | consumed/s | GiB/s | kernelDrop | perConnDrop |
|---|---|---|---|---|---|---|
| 50,000 | 1 | 49,999 | 49,999 | 0.21 | 0 | 0 |
| 50,000 | 2 | 49,999 | 49,999 | 0.21 | 0 | 0 |
| 50,000 | 3 | 49,999 | 49,999 | 0.21 | 0 | 0 |
| 100,000 | 1 | 99,999 | 99,999 | 0.42 | 0 | 0 |
| 100,000 | 2 | 99,999 | 99,999 | 0.42 | 0 | 0 |
| 100,000 | 3 | 99,999 | 99,999 | 0.42 | 0 | 0 |
| 200,000 | 1 | 199,997 | 199,997 | 0.84 | 0 | 0 |
| 200,000 | 2 | 199,997 | 199,997 | 0.84 | 0 | 0 |
| 200,000 | 3 | 199,997 | 199,997 | 0.84 | 0 | 0 |
| 300,000 | 1 | 299,996 | 299,996 | 1.26 | 0 | 0 |
| 300,000 | 2 | 299,996 | 299,996 | 1.26 | 0 | 0 |
| 300,000 | 3 | 299,996 | 299,996 | 1.26 | 0 | 0 |
| 500,000 | 1 | 497,879 | 497,879 | 2.09 | 0 | 5,477 (1.1%) |
| 500,000 | 2 | 391,916 | 387,894 | 1.63 | 0 | 9,406 (2.4%) |
| 500,000 | 3 | 499,993 | 499,993 | 2.10 | 0 | 12,500 (2.5%) |

## GOMAXPROCS=2 · parse-on  (full pipeline: parse + no-op produce)

| rate/s | run | offered/s | consumed/s | GiB/s | kernelDrop | perConnDrop | cov% |
|---|---|---|---|---|---|---|---|
| 50,000 | 1 | 49,999 | 49,999 | 0.21 | 0 | 0 | 99.9 |
| 50,000 | 2 | 49,999 | 49,999 | 0.21 | 0 | 0 | 99.9 |
| 50,000 | 3 | 49,999 | 49,999 | 0.21 | 0 | 0 | 99.9 |
| 100,000 | 1 | 99,999 | 99,999 | 0.42 | 0 | 0 | 100.0 |
| 100,000 | 2 | 99,999 | 99,999 | 0.42 | 0 | 0 | 100.0 |
| 100,000 | 3 | 99,999 | 99,999 | 0.42 | 0 | 0 | 100.0 |
| 200,000 | 1 | 199,997 | 199,997 | 0.84 | 0 | 1,600 (0.8%) | 99.1 |
| 200,000 | 2 | 195,615 | 195,615 | 0.82 | 0 | 2,739 (1.4%) | 98.6 |
| 200,000 | 3 | 199,997 | 199,997 | 0.84 | 0 | 0 | 100.0 |
| 300,000 | 1 | 265,023 | 254,518 | 1.07 | 6,096 (2.3%) | 38,428 (14.5%) | 83.0 |
| 300,000 | 2 | 268,916 | 240,714 | 1.01 | 9,681 (3.6%) | 36,841 (13.7%) | 82.6 |
| 300,000 | 3 | 291,264 | 241,531 | 1.01 | 49,806 (17.1%) | 17,476 (6.0%) | 76.9 |
| 500,000 | 1 | 329,051 | 308,143 | 1.29 | 3,291 (1.0%) | 73,049 (22.2%) | 76.6 |
| 500,000 | 2 | 269,419 | 189,354 | 0.79 | 64,391 (23.9%) | 26,134 (9.7%) | 66.2 |
| 500,000 | 3 | 318,111 | 305,920 | 1.28 | 12,088 (3.8%) | 62,350 (19.6%) | 76.4 |

## GOMAXPROCS=4 · parse-off

| rate/s | run | offered/s | consumed/s | GiB/s | kernelDrop | perConnDrop |
|---|---|---|---|---|---|---|
| 50,000 | 1 | 49,999 | 49,999 | 0.21 | 0 | 0 |
| 50,000 | 2 | 49,999 | 49,999 | 0.21 | 0 | 0 |
| 50,000 | 3 | 49,999 | 49,999 | 0.21 | 0 | 0 |
| 100,000 | 1 | 99,999 | 99,999 | 0.42 | 0 | 0 |
| 100,000 | 2 | 99,999 | 99,999 | 0.42 | 0 | 0 |
| 100,000 | 3 | 99,998 | 99,998 | 0.42 | 0 | 0 |
| 200,000 | 1 | 199,997 | 199,997 | 0.84 | 0 | 0 |
| 200,000 | 2 | 199,997 | 199,997 | 0.84 | 0 | 0 |
| 200,000 | 3 | 199,719 | 199,719 | 0.84 | 0 | 0 |
| 300,000 | 1 | 299,996 | 299,996 | 1.26 | 0 | 0 |
| 300,000 | 2 | 299,996 | 299,996 | 1.26 | 0 | 0 |
| 300,000 | 3 | 299,996 | 299,996 | 1.26 | 0 | 0 |
| 500,000 | 1 | 499,993 | 499,993 | 2.10 | 0 | 5,000 (1.0%) |
| 500,000 | 2 | 390,597 | 382,287 | 1.60 | 8,202 (2.1%) | 391 (0.1%) |
| 500,000 | 3 | 499,993 | 499,993 | 2.10 | 0 | 500 (0.1%) |

## GOMAXPROCS=4 · parse-on

| rate/s | run | offered/s | consumed/s | GiB/s | kernelDrop | perConnDrop | cov% |
|---|---|---|---|---|---|---|---|
| 50,000 | 1 | 49,999 | 49,999 | 0.21 | 0 | 0 | 99.9 |
| 50,000 | 2 | 49,999 | 49,999 | 0.21 | 0 | 0 | 99.9 |
| 50,000 | 3 | 49,665 | 49,665 | 0.21 | 0 | 0 | 99.9 |
| 100,000 | 1 | 99,999 | 99,999 | 0.42 | 0 | 0 | 100.0 |
| 100,000 | 2 | 99,998 | 99,998 | 0.42 | 0 | 0 | 100.0 |
| 100,000 | 3 | 99,999 | 99,999 | 0.42 | 0 | 0 | 100.0 |
| 200,000 | 1 | 199,997 | 199,997 | 0.84 | 0 | 0 | 100.0 |
| 200,000 | 2 | 199,997 | 199,997 | 0.84 | 0 | 0 | 100.0 |
| 200,000 | 3 | 199,997 | 199,997 | 0.84 | 0 | 0 | 100.0 |
| 300,000 | 1 | 299,996 | 299,996 | 1.26 | 0 | 1,800 (0.6%) | 99.4 |
| 300,000 | 2 | 299,996 | 298,950 | 1.25 | 900 (0.3%) | 2,100 (0.7%) | 99.0 |
| 300,000 | 3 | 299,996 | 299,996 | 1.26 | 0 | 1,200 (0.4%) | 99.6 |
| 500,000 | 1 | 75,734 | 56,850 | 0.24 | 15,677 (20.7%) | 6,362 (8.4%) | 70.7 |
| 500,000 | 2 | 409,359 | 371,017 | 1.56 | 18,831 (4.6%) | 22,924 (5.6%) | 89.8 |
| 500,000 | 3 | 84,431 | 83,905 | 0.35 | 0 | 1,773 (2.1%) | 97.7 |

---

## Scaling summary

| config | clean ceiling | collapses at |
|---|---|---|
| parse-off @ 2 | 300K (1.26 GiB/s) | ~500K (variance) |
| parse-off @ 4 | 300K (1.26 GiB/s) | ~500K (variance) |
| parse-on  @ 2 | ~100–200K (0.42–0.84 GiB/s) | 300K |
| parse-on  @ 4 | **300K (1.26 GiB/s)** | 500K |

- **parse-on scales with cores:** 2→4 cores moves the clean ceiling ~200K → 300K
  and the collapse ~300K → 500K. Parse is the parallel worker path.
- **parse-off (ingest) barely changes with cores** (300K clean, 500K variance at
  both 2 and 4). Ingest is bound by the single-goroutine reader + light tracker
  store, not by parallelism — extra cores don't help it much.
- **The collapse is metastable/bimodal at the ceiling** (thundering-herd of
  runnable goroutines on the P's) — same failure seen in the real `kafka-on`
  benchmark, reproduced synthetically. The tip moves up with more cores. Note the
  signature: at collapse, `perConnDrop` and `kernelDrop` spike together and
  `offered/s` itself falls below target (the producer shares the starved P's).

## Caveats

1. **No `cgocall`/BCC reader cost** — the harness feeds `eventChan` directly, so
   these are **upper bounds**. Production (perf-buffer reader competing for the
   same P's) hits the ceiling and the collapse at **lower** rates.
2. **parse-off `cov=—` by design** (no pairing runs); it measures ingest capacity
   only, and doesn't drain pairs (memory grows over the window).
3. Throughput is **wire bytes** (attr+payload); payload-only is ~1–2% lower.
   Drop counts are derived (`offered × pct`), so ±1 in the last digit.

## Conclusions

- **100K events/s (0.42 GiB/s):** sustained with 0 drops in every config; it is the
  *ceiling* only for parse-on @ 2 cores.
- **1 GiB/s (~300K events/s):** **reachable with parse on only at ≥4 cores**
  (1.26 GiB/s @ ~99–100% coverage, stable). At 2 cores parse-on collapses at 300K.
  The ingest path alone does 1.26 GiB/s even at 2 cores.
- **GOMAXPROCS is the recurring lever.** Every ceiling and every collapse here (and
  in the real benchmarks) traces to too few P's: 2 caps parse at ~0.4–0.8 GiB/s and
  tips at 300K; 4 gets a stable 1.26 GiB/s with parse on, tipping at 500K.
