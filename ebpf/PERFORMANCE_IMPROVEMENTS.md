# eBPF traffic collector — performance improvements

What improved in the latest collector builds, why it matters, and what you can tune.

---

## At a glance

| Area | Improvement | Why it matters |
|---|---|---|
| **Event path** | Capture events are handled inline (no large intermediate queues) | Lower CPU and memory under high traffic; less backlog |
| **Kernel buffers** | Larger, tunable data / open / close buffers; data path split across **8** parallel shards | Fewer dropped events under load; better throughput |
| **Logging** | Verbose ingest/process logs only when explicitly enabled | Avoids log overhead when capture is busy |
| **Noise filtering** | Loopback filter + optional ignore of infra ports (Kafka, Mongo, Redis, ZooKeeper) | Less wasted work; more capacity for real API traffic |
| **Host CPU protection** | Soft pause / hard restart based on host system CPU | Protects other workloads; the module backs off instead of saturating the host |
| **Observability** | Drop and memory signals available; map memory reported once at start | Easier to spot loss without ongoing reporting cost |

---

## 1. Faster, leaner event processing

**Before:** events moved through large intermediate queues before they were handled (extra copies, allocations, and delay).

**After:**

- Events are processed directly as they are read from the kernel.
- Readers reuse buffers instead of allocating a new one for every event.
- Large intermediate queues between read and handling were removed.

**Effect:** lower CPU and memory per event, and less chance of a large in-memory backlog when traffic spikes.

---

## 2. Kernel buffers: capacity and parallelism

**Capacity**

- Default data / open / close buffers are much larger than in older builds (on the order of hundreds of MiB for data, tens of MiB for open/close).
- Sizes are tunable so you can trade memory for fewer drops:
  - `TRAFFIC_RINGBUF_DATA_MB` — default total **512** MiB across data shards
  - `TRAFFIC_RINGBUF_OPEN_MB` — default **64**
  - `TRAFFIC_RINGBUF_CLOSE_MB` — default **64**

**Parallelism**

- Data events are spread across **8** buffer shards and drained in parallel.
- This reduces contention and improves throughput when many connections are active.

**Effect:** fewer lost events under bursty API traffic, at a controlled memory cost.

---

## 3. Less work on traffic you do not need

- **Loopback** traffic can be filtered (`FILTER_LOCAL_TRAFFIC`, default on).
- Common infra ports (Kafka, ZooKeeper, Mongo, Redis) can be skipped (`TRAFFIC_IGNORE_DEFAULT_PORTS`, default on).

**Effect:** CPU and buffers spend more time on application API traffic.

---

## 4. Host CPU soft / hard limits

The module measures **host system (kernel) CPU**, takes a baseline at startup, then:

- **Soft** (baseline + 2 cores by default) → **pauses** capture until CPU recovers  
- **Hard** (baseline + 3 cores by default) → **restarts** after a sustained breach  

See [OPERATING_LIMITS.md](./OPERATING_LIMITS.md) for full tuning.

**Effect:** under host pressure, the collector backs off instead of competing indefinitely with production workloads.

---

## 5. Lighter observability

- Submit success/failure counters can be logged to help detect silent drops.
- eBPF map memory is reported **once at startup** (not on a continuous timer), which cuts ongoing log and CPU cost.
- Capture can be force-paused with `AKTO_PAUSE_INGESTION` for emergency load shedding without uninstalling.

**Effect:** you can diagnose loss and memory use without a constant reporting overhead.

---

## What to tune after upgrade

| Goal | Start with |
|---|---|
| Fewer dropped events | Raise `TRAFFIC_RINGBUF_DATA_MB` / open / close (if RAM allows) |
| Lower host impact | Lower `AKTO_SYSTEM_CPU_SOFT_ADD_CORES` (see the CPU limits guide) |
| Lower memory | Lower ring-buffer sizes |
| Ignore infra chatter | Keep `TRAFFIC_IGNORE_DEFAULT_PORTS=true` and the local-traffic filter on |
| Investigate drops | Enable submit stats and review the startup map-memory snapshot |
