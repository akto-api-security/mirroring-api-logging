---
name: rate-sweep-baseline
description: Run the rate-sweep capacity baseline (3 non-kafka + 3 kafka configs x 3 runs) against ebpf/connections/callback_ratesweep_test.go and (optionally) diff it against a prior baseline's metrics. Use when the user says "run a rate-sweep baseline", "baseline today", or asks to re-run/compare the callback rate sweep.
---

# Rate-sweep baseline (zero-config)

Runs the standard capacity baseline — parse-off and parse-on/json always;
parse-on/json+kafka and parse-on/json+kafka+threat if `kafka-internal` is up
(3 runs each) — and, if asked, diffs the resulting metrics against a prior
baseline. ebpf-core has only the JSON encoder, so there are no flatbuffers
configs (older feature/k8s_ebpf baselines had them).

What the harness drives in ebpf-core: a paced producer builds the kernel's
records (64-byte header + ≤ 30 KB chunk), picks the ring by connection hash and
keeps the kernel's lost-byte accounting; one consumer per ring calls the real
`Shard.HandleRecord`. Every request carries a unique `X-Request-Id`, and every
emitted pair is checked: `pairs_mismatched` must be 0 at every tier. See the
header of `ebpf/connections/callback_ratesweep_test.go`. All mechanics live in `scripts/`; this file only covers
what needs judgment.

The `+threat` config additionally exercises the second, protobuf-based Kafka produce
path (`kafkaUtil.Produce` → `akto.api.logs2`, gated by `-threat`/`utils.ThreatEnabled`)
that runs alongside the normal encoded-payload produce on every parsed pair — a
distinct extra cost path the other configs never touch.

## Step 1 — run the sweep

```bash
bash skills/rate-sweep-baseline/scripts/run-sweep.sh
```

No arguments needed — it uses today's date as the prefix (e.g. `8-aug`). Pass
an explicit prefix as `$1` only if the user asks for one, or if today's default
prefix already has a baseline (the script refuses to run and exits if
`connections/pprof/<prefix>-*-r*` already exists, rather than overwriting it —
if that happens, re-invoke with an explicit disambiguated prefix like `8-aug-2`).

The script:
- Refuses to run if the prefix's output dirs already exist (no clobbering a same-day baseline).
- Runs `go vet`/`go test -short` first and aborts before the full matrix if that fails.
- Checks `kafka-internal` is up+healthy; if not, runs the 3 non-kafka configs
  only and says so — does not hang waiting for a broker.
- Runs all applicable configs x 3, **never stopping the matrix on one config's
  failure** (an unexpected early OOM, a broker hiccup, etc.) — logs it inline
  and continues to the next config/run. Report any such anomaly to the user.
- Writes to `ebpf/connections/pprof/<prefix>-<config>-r<N>/` (the test's own
  existing layout — nothing new invented, `stdout.log` is the only addition,
  used solely to detect the OOM-kill line for a tier that never finished).

This takes roughly 10–15 minutes (longer if all 4 configs run). Tell the user
before starting if they didn't already ask for the full matrix explicitly.

## Step 2 — parse

```bash
python3 ../skills/rate-sweep-baseline/scripts/parse_results.py <prefix> > /tmp/<prefix>.json
```

Run from `ebpf/`. Aggregates **every** run dir matching `<prefix>-<config>-r<N>`
under `connections/pprof/` — however many exist, not hardcoded to 3, so it also
picks up manually re-run configs under the same prefix.

Output is raw per-tier numbers only (coverage_pct, drop counters, completed
y/n) — **no computed "clean ceiling" or pass/fail verdict**. A tier can have
metrics.json (the process survived it) yet still show real drops; collapsing
that into one scalar bakes in a threshold judgment call, which is left to
whoever reads the numbers (or writes the report), not this script.

## Step 3 — diff against a prior baseline (only if asked)

```bash
python3 ../skills/rate-sweep-baseline/scripts/diff_metrics.py /tmp/<priorPrefix>.json /tmp/<todayPrefix>.json
```

This is metrics-only, tier-by-tier: completed count, coverage_pct range,
kernel/channel-drop range, parse-failure range, prior → today. No git history,
no commit correlation, no causal narrative — if the user wants to know *why*
a number moved, that's a separate, explicit ask (they'll tell you which
investigation to run; don't infer it here).

**The user must name which prior baseline to diff against** (e.g. "compare to
7-aug") — do not auto-discover or guess the most recent one.

## Hard rule carried over from a past mistake

**Never attribute a metrics change to a specific commit, flag, or code path
without first grepping the actual call sites to confirm it's live in this
harness.** A prior baseline report incorrectly blamed a regression on two
feature flags that turned out to be hardcoded `false` by the test itself the
entire time — the theory was built from a commit message and a doc comment,
not from checking where the flag was actually read. If asked to explain a
diff's cause (a separate task from this skill), verify against source before
writing any explanation down.

## Reporting

If the user wants a written report (not just the diff output), match the
existing format in `mdfiles/<date>-rate-sweep-results.md` files: per-config
tables with the sweep's own log columns (offered/consumed/kernelDrop%/
perConnDrop%/cov%/status). Do not add a "what changed in the code" section
unless the user explicitly asks for one — this skill's scope is running and
comparing, not investigating causes.
