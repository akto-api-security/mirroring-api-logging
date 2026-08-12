# eBPF traffic collector — host CPU limits

This guide explains how the Akto eBPF collector protects the host from excess **system (kernel) CPU** load, and how you can tune that behavior.

---

## What it does

The collector watches **host-wide system CPU** (kernel time on the machine), not only the CPU of the Akto process or container.

| Limit | Default behavior | Effect on the module |
|---|---|---|
| **Soft** | Baseline host system CPU + **2 cores** | Capture **pauses**. No new traffic is ingested until CPU falls back under the soft limit, then capture **resumes**. |
| **Hard** | Baseline host system CPU + **3 cores** | Module **stops** after a few consecutive breaches (default **3** checks). The supervisor **restarts** it. |

**Baseline:** at startup, before capture fully starts, the module samples host system CPU for a short window (default **15 seconds**) and uses a high percentile (P90) as the baseline. Soft/hard limits are then baseline + your configured extra cores—unless you set absolute core limits instead.

This is **independent** of Kubernetes or Docker CPU quotas (e.g. `500m`, `--cpus`). Those throttle the container at the OS level; they do not replace soft/hard pause and restart logic.

---

## Lifecycle

1. Measure baseline host system CPU (startup window).
2. Set soft and hard limits (baseline + add cores, or absolute values you set).
3. Check about once per second.
4. **Above soft** → pause ingest. **Below soft** → resume.
5. **Above hard** for several checks in a row → exit (code **4**) → restart.
6. If soft pause/resume **keeps flipping** too often (default **1800** flips) → exit (code **5**) → restart so baseline can be measured again.

---

## Settings

| Setting | Default | What it controls | How it affects the module |
|---|---|---|---|
| `AKTO_SYSTEM_CPU_SOFT_ADD_CORES` | `2` | Extra cores above baseline for the soft limit | Lower → pauses sooner (more host-friendly, less capture under load). Higher → captures longer before pausing. |
| `AKTO_SYSTEM_CPU_HARD_ADD_CORES` | `3` | Extra cores above baseline for the hard limit | Lower → restarts sooner under load. Higher → tolerates more host system CPU before restart. Set `≤0` (and no absolute hard) to **disable** CPU limiting. |
| `AKTO_SYSTEM_CPU_SOFT_CORES` | unset | Absolute soft limit in cores | Overrides soft-add. Pause when host system CPU ≥ this value. |
| `AKTO_SYSTEM_CPU_HARD_CORES` | unset | Absolute hard limit in cores | Overrides hard-add. Restart when host system CPU stays ≥ this value. Set `≤0` to **disable** CPU limiting. |
| `AKTO_SYSTEM_CPU_CHECK_INTERVAL_SEC` | `1` | Seconds between CPU checks | Higher → slower reaction to spikes; lower → faster pause/resume. |
| `AKTO_SYSTEM_CPU_BASELINE_SAMPLE_SEC` | `15` | Startup baseline window (seconds) | Longer → stabler baseline on noisy hosts; shortens time before capture starts. |
| `AKTO_SYSTEM_CPU_BASELINE_STEP_SEC` | `1` | Sampling step during baseline | Usually leave at default. |
| `AKTO_SYSTEM_CPU_HARD_CONFIRM_TICKS` | `3` | Consecutive hard breaches before restart | Higher → ignores brief spikes; lower → restarts faster on sustained breach. |
| `AKTO_SYSTEM_CPU_SOFT_OSCILLATION_EXIT_TRANSITIONS` | `1800` | Soft pause/resume flip count before restart | Triggers a restart so baseline can be re-measured if soft limit is thrashing. |
| `AKTO_PAUSE_INGESTION` | `false` | Force pause all ingest | Module stays up but does not capture until set back to `false` and process picks up the setting (typically on restart if set via env at start). |

---
