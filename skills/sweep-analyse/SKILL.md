---
name: sweep-analyse
description: Analyze pprof/metrics output produced by the ebpf/connections/callback_ratesweep_test.go rate-sweep harness (either a single ad-hoc `-testname=... -rps=... -window=...` run, or a full rate-sweep-baseline sweep with `<prefix>-<config>-r<N>` dirs) by fanning out 3 parallel subagents (metrics, CPU+goroutines+mutex, heap trajectory) and consolidating into one report. Use when the user says "analyze this run/testname/sweep", pastes rate-sweep test output, or names a connections/pprof/<name> directory to inspect. Distinct from `bench-analyze`, which reads the OLDER traffic-generator/logs/<prefix>-N/ layout — this skill reads the current ebpf/connections/pprof/ layout the rate-sweep-baseline skill and manual `go test -run TestRateSweep` invocations both produce.
---

# Rate-sweep pprof analysis (parallel fan-out)

Analyzes runs produced by `ebpf/connections/callback_ratesweep_test.go` — either:

- **A single ad-hoc run**, e.g.
  `go test -run TestRateSweep ... -args -testname=26-aug-json-encode-300k -rps=300k -window=120s ...`
  → data lands at `ebpf/connections/pprof/<testname>/<arm>/[<encoder>/]<rate>/`.
- **A full baseline sweep** via `rate-sweep-baseline`'s `run-sweep.sh <prefix>`
  → data lands at `ebpf/connections/pprof/<prefix>-<config>-r<N>/<arm>/[<encoder>/]<rate>/`
  for each of the 2-4 configs × 3 runs. See `skills/rate-sweep-baseline/SKILL.md`
  and its `scripts/parse_results.py` for the exact naming/grouping convention
  (`CONFIG_LAYOUT`, `RATES = [50k,100k,200k,300k,500k]`) — reuse that convention
  here rather than reinventing it.

## Step 0 — locate data, note gaps

Determine which shape you're dealing with:

```bash
# single ad-hoc testname — dir exists directly
ls ebpf/connections/pprof/<name>/

# baseline sweep — <name> is a PREFIX, dirs are <name>-<config>-r<N>
ls -d ebpf/connections/pprof/<name>-*-r*/
```

For whichever dirs you find, list what's actually inside each `<arm>/[<encoder>/]<rate>/`
cell — do NOT assume all files exist (a cell that OOM'd mid-run may be missing
`metrics.json`, `heap-final.prof`, or the later `heap-N.prof` snapshots):

```bash
ls ebpf/connections/pprof/<run-dir>/<arm>/[<encoder>/]<rate>/
```

Expected files per cell: `metrics.json`, `cpu.prof`, `heap-0.prof`, `heap-1.prof`,
`heap-2.prof`, ... (periodic, ~10s apart), `heap-final.prof` (forced-GC end state),
`goroutine-count.tsv` (plain-text elapsed_sec/num_goroutine trajectory, sampled
alongside the heap snapshots), `goroutine.prof` (end-of-run snapshot), `allocs.prof`,
`mutex.prof`, `block.prof`. A sibling `stdout.log` exists ONLY if the run went
through `run-sweep.sh` (or the user redirected output themselves) — if the user
pasted terminal output instead, use that directly for the OOM/watchdog line
(`"Refreshing, current {alloc,sys} mem usage" mem=X threshold=Y`) rather than
assuming a log file exists.

Pass the actual file inventory to each subagent so they report "not captured"
rather than erroring on a missing file.

## Step 1 — spawn 3 subagents IN PARALLEL

Send all three in a single message (multiple Agent tool_uses) so they run
concurrently. Use `general-purpose` agents. Each gets the file inventory from
Step 0, the run's own config (rate, encoder, kafka/threat on-or-off — from the
directory path and/or the command the user ran), and this grounding:

```
Read these in full before anything else — they are the authoritative, current
description of this pipeline, the harness and its metrics. Do not re-derive
pipeline structure or guess at a metric's meaning; these already answer that:
  docs/PAIRING_CAPTURE_CHANGESET.md   (design, pairing proof, loss counters)
  ebpf/connections/callback_ratesweep_test.go   (header comment: what is driven,
    what each metrics.json field means)
Ground every claim in (a) these docs, (b) source you personally read at a
specific file:line, or (c) pprof/tsv/json output you personally read — never in
general knowledge you have not verified applies HERE.
```

pprof source mapping for any `-list` command:
`-trim_path=/ -source_path=<this repo's root>`

**Agent A — metrics:** for each rate-tier cell, read `metrics.json` if present
(`python3 -m json.tool`). Compare across cells/runs: `events_received`,
`duration_sec` (→ events/sec), `events_dropped_kernel_ring_buf`,
`events_dropped_channel_full` (should be 0 — red flag otherwise),
`input_chan_len` (records still queued at window end) vs `ring_bytes_cap`,
`pairs_attempted/parse_success`, **`pairs_mismatched` (must be 0 — any other
value is a pairing bug, report it first)**, `coverage_pct`, and the capture
counters that explain every miss: `lost_bytes`, `desyncs`, `orphans`,
`truncated_pairs`, `unanswered_at_end`, `pipelined_*`, `mem_wiped_conns`.
(`groups_*`, `gap_skip*`, `late_arrivals` belong to feature/k8s_ebpf's
`msg_seq` design and don't exist here.) If a cell has no `metrics.json`, that run died before finishing
it — pull the OOM line from `stdout.log` (or the user-pasted output) if
available, and report which tier it died at as a fact, not a guess. Watch for
run-over-run degradation across `-r<N>` runs of the same config, and for
degradation across rate tiers within one run.

**Agent B — CPU + goroutines + mutex + block:**
- CPU: `go tool pprof -top -nodecount=10 cpu.prof` — capture the **raw top-10
  table verbatim** (flat/flat%/sum%/cum/cum%/name), then `-list=<funcname>` on
  the top application-level (non-runtime) function for line attribution.
- Goroutines: **read `goroutine-count.tsv` directly** (plain tsv, no pprof
  needed) — capture the full elapsed_sec/num_goroutine sequence, not just an
  end value. Do NOT rely solely on the end-of-run `goroutine.prof` snapshot,
  which only shows the post-drain idle floor and is useless for spotting
  growth during load. This is a hard-learned rule from a past investigation on
  this exact harness — classify the shape explicitly: growing / oscillating
  (bounded, expected connection churn) / erratic sawtooth (repeated boom-bust,
  flag as worth investigating) / flat.
- Mutex: `go tool pprof -top -nodecount=10 mutex.prof` — raw top-10 table,
  then `-list=<funcname>` on the top contended function, then `-traces` (or
  read the tree from `-top`'s callers) to identify which specific caller
  function accounts for the largest cumulative wait. Mutex-profile delay is
  attributed to the BLOCKED caller, not the lock holder — state explicitly
  which function's callers were waiting and for how long before claiming a
  contention direction.
- Block: `go tool pprof -top -nodecount=10 block.prof` — raw top-10 table.
  Expect `runtime.selectgo` idle-wait in worker `select` loops to dominate
  (not a contention signal); flag anything else as a genuine finding.

**Agent C — heap TRAJECTORY (not a single snapshot):** for each cell, run
`go tool pprof -top -nodecount=10 -inuse_space` against `heap-0.prof`, then
`heap-1.prof`, `heap-2.prof`, ... in sequence, then `heap-final.prof`. Report
the FULL sequence of totals (not just start/end) and state explicitly whether
it's growing, flat, or oscillating across the run. **Do not use
`heap-final.prof` alone as primary evidence** — it's a forced-GC end state,
useful only as one more trajectory point. This is a hard-learned rule: an
earlier pass on this exact harness wrongly characterized "healthy" using only
the end-of-run snapshot and missed what was happening mid-load. Also capture
the **raw top-10 table** for `-alloc_space allocs.prof` (churn — continuously
freed by GC, large numbers expected, not itself evidence of a problem unless
the inuse trajectory also grows). Use `-list=<funcname>` for line-level
attribution of the top 2-3 items in both inuse and alloc tables.

## Step 2 — consolidate

Output structure — **raw top-10 tables first, prose only in a closing
findings/suggestions section.** No narrated walkthroughs of what each profile
"shows" in paragraph form; the tables ARE the evidence.

```
## metrics
| field | value |
|---|---|
(only the fields that matter: drops, gap-skips, coverage_pct — not every field)

## CPU — top 10 (cpu.prof)
| flat | flat% | cum | cum% | function |
|---|---|---|---|---|
(paste the real pprof -top10 rows verbatim, one table per cell/run if there
are several — do not paraphrase the numbers into prose)

## Goroutines — trajectory (goroutine-count.tsv)
| elapsed_sec | num_goroutine |
|---|---|
(full sequence) -> shape: growing / oscillating / erratic sawtooth / flat

## Mutex — top 10 (mutex.prof)
| flat | flat% | cum | cum% | function |
|---|---|---|---|---|
Blocked-caller attribution: <function X> callers waited <N>s total, vs
<function Y> callers waited <M>s total. Direction: <which side is starving
which, stated as a ratio, not just "there is contention">.

## Block — top 10 (block.prof)
| flat | flat% | cum | cum% | function |
|---|---|---|---|---|

## Heap — trajectory (heap-N.prof, inuse_space)
| snapshot | inuse total |
|---|---|
(full sequence, heap-0 through heap-final) -> shape: growing / oscillating / flat
Top holder(s) per snapshot: <function, file:line, whether it's test-harness or pipeline code>

## Alloc churn — top 10 (allocs.prof, alloc_space)
| flat | flat% | cum | cum% | function |
|---|---|---|---|---|
```

Then a **mandatory closing section**:

```
## Findings + app-side code suggestions

For each real (non-harness, non-expected-idle) finding surfaced by the tables
above, give:
- **What**: the specific metric/profile evidence (numbers, not adjectives).
- **Where**: exact file:line of the implicated function(s) — read the actual
  current source before naming a line, don't rely on the pprof symbol name
  alone (it can drift from the current file).
- **Why** (only if independently verified against source — not a guess):
  the mechanism, e.g. "AddDataEvent's per-event lock acquisition frequency
  (~N/sec/conn) is starving GetFlushablePairs (ticks every 500ms) of
  tracker.mutex, per mutex.prof's blocked-caller attribution above."
- **Suggested change**: a concrete, specific code-level suggestion (e.g.
  "shrink GetFlushablePairs' critical section by copying the pending
  msgGroups keys under lock, then doing the pairing/orphan bookkeeping in
  drainPairs outside the lock, re-acquiring only to commit
  lowestPendingSeq/delete") — not generic advice ("optimize the hot path").
  If the fix is a config/capacity lever (e.g. raise GOMAXPROCS) rather than a
  code change, say so explicitly instead of forcing a code suggestion where
  none is warranted.
- **Confidence**: high (mechanism directly verified in source + profile) /
  medium (profile evidence is clear but the code-level mechanism is inferred,
  not yet confirmed by re-measuring a fix) / low (correlated but unexplained
  — e.g. an erratic goroutine trajectory that isn't yet tied to a specific
  cause).

Explicitly separate test-harness cost (e.g. `rsWrap`, `rsEmit`,
`connections.TestRateSweep`) from pipeline application code — harness cost is
not something to "fix" in app code, say so and move on rather than proposing
changes to it.
```

## Hard rules carried over from past mistakes on this harness

1. **Trajectory, not snapshot.** Heap and goroutine health must be judged
   across all periodic samples, never a single end-of-run number.
2. **Never attribute a metric change to a specific flag/commit/code path
   without first grepping the actual call sites to confirm it's live in this
   run's config.** A past investigation blamed a regression on flags that
   turned out hardcoded `false` the whole time — the theory came from a doc
   comment, not verified source.
3. **Kafka is a separate concern from the core pipeline.** If `-kafka=false`
   (or the dir path has no `-kafka`/`-threat` suffix), do not analyze or
   propose fixes involving `kafkaUtil`/`kafka-go` internals — a past
   regression was shown to reproduce even without Kafka, so don't assume it's
   implicated by default.
4. **`AKTO_MEM_THRESH_RESTART`/`AKTO_SYS_MEM_HARD_LIMIT` matter for
   interpretation.** If these weren't set for the run being analyzed, the
   hardcoded defaults (500MB alloc / 950MB sys, see `trafficUtil/utils/stats.go`)
   apply and the run may have died far earlier than the baseline convention
   (1800/2048) would suggest — check the run's actual env/command before
   comparing its OOM point to a baseline report's numbers.
