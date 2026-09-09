package kafkaUtil

// This file owns the cross-cutting policy + observability concerns that decide
// whether/how much traffic is processed and record what happened: runtime
// configuration (env vars + init), request filtering, body sampling
// (bloom/LRU), debug-URL logging, bandwidth limiting, and outgoing metrics.

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/fastparser"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/trafficMetrics"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
	bloomfilter "github.com/bits-and-blooms/bloom/v3"
)

var (
	goodRequests               = 0
	badRequests                = 0
	debugMode                  = false
	fastEncoderKind            = "json" // FAST_ENCODER: wire format on the fast path ("json" | "flatbuffers")

	// SkipPairProcessing, when true, returns from ParseAndProduce just before
	// parseHTTPTraffic — no HTTP parse, no marshal, no produce. Used to isolate the
	// parse CPU cost (benchmarks / the "disable-pair-process" experiments).
	SkipPairProcessing = false
	outputBandwidthLimitPerMin = -1
	currentBandwidthProcessed  = 0
	lastSampleUpdate           = time.Now().Unix()
	sampleMutex                = sync.RWMutex{}
	injectTagsMap              = map[string]string{}
	methodsMap                 = map[string]bool{
		"GET":     true,
		"HEAD":    true,
		"POST":    true,
		"PUT":     true,
		"DELETE":  true,
		"CONNECT": true,
		"OPTIONS": true,
		"TRACE":   true,
		"TRACK":   true,
		"PATCH":   true}
	DebugStrings = []string{}

	EventChanBuffSize = 100000

	// Body parsing optimization variables
	lruCache            *LRUCache
	lruCacheCapacity    = 100000
	bloomFilterCapacity = 1000000
	bloomFilterFPRate   = 0.01
	timeBucketDuration  = 10 * time.Minute
	memSamplingEnabled  = false
)

var bloomFilter *bloomfilter.BloomFilter

const ONE_MINUTE = 60

// SetFastEncoder overrides the fast-path wire encoder ("json" | "flatbuffers")
// at runtime, e.g. from a test harness. Must be called before the first
// fastParseAndProduce (encoderPool is lazy: it builds on first Get, reading
// fastEncoderKind at that moment). Returns false and leaves the kind unchanged
// if kind is not a valid encoder.
func SetFastEncoder(kind string) bool {
	if !fastparser.ValidEncoder(kind) {
		return false
	}
	fastEncoderKind = kind
	return true
}

func init() {
	utils.InitVar("DEBUG_MODE", &debugMode)
	utils.InitVar("SKIP_PAIR_PROCESSING", &SkipPairProcessing)
	utils.InitVar("FAST_ENCODER", &fastEncoderKind)
	if !fastparser.ValidEncoder(fastEncoderKind) {
		slog.Warn("unknown FAST_ENCODER, falling back", "value", fastEncoderKind, "fallback", "json")
		fastEncoderKind = "json"
	}
	utils.InitVar("OUTPUT_BANDWIDTH_LIMIT", &outputBandwidthLimitPerMin)
	utils.InitVar("EVENT_CHAN_BUFF_SIZE", &EventChanBuffSize)
	utils.InitVar("AKTO_MEM_SAMPLING_ENABLED", &memSamplingEnabled)
	utils.InitVar("LRU_CACHE_CAPACITY", &lruCacheCapacity)
	utils.InitVar("BLOOM_FILTER_CAPACITY", &bloomFilterCapacity)
	utils.InitVar("BLOOM_FILTER_FP_RATE", &bloomFilterFPRate)
	utils.InitVar("TIME_BUCKET_DURATION_MINUTES", &timeBucketDuration)

	// convert MB to B
	if outputBandwidthLimitPerMin != -1 {
		outputBandwidthLimitPerMin = outputBandwidthLimitPerMin * 1024 * 1024
	}
	debugStringsEnv := ""
	utils.InitVar("DEBUG_URLS", &debugStringsEnv)
	if len(debugStringsEnv) > 0 {
		DebugStrings = strings.Split(debugStringsEnv, ",")
	}
	slog.Info("debugStrings", "DebugStrings", DebugStrings)

	// Only initialize Bloom Filter and LRU Cache if memory sampling is enabled
	if memSamplingEnabled {
		bloomFilter = bloomfilter.NewWithEstimates(uint(bloomFilterCapacity), bloomFilterFPRate)

		// Initialize LRU Cache
		lruCache = NewLRUCache(lruCacheCapacity)

		// Reset Bloom filter every 24 hours to prevent permanent false positives
		go func() {
			ticker := time.NewTicker(24 * time.Hour)
			defer ticker.Stop()
			for range ticker.C {
				bloomFilter.ClearAll()
			}
		}()
	}

	injectTagsEnv := ""
	utils.InitVar("AKTO_INJECT_TAGS", &injectTagsEnv)
	if injectTagsEnv != "" {
		for _, pair := range strings.Split(injectTagsEnv, ";") {
			pair = strings.TrimSpace(pair)
			if idx := strings.IndexByte(pair, '='); idx > 0 {
				k := strings.TrimSpace(pair[:idx])
				v := strings.TrimSpace(pair[idx+1:])
				if k != "" {
					injectTagsMap[k] = v
				}
			}
		}
		slog.Info("AKTO_INJECT_TAGS loaded", "tags", injectTagsMap)
	}

	// Start ticker to read debug URLs from file every 30 seconds
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			UpdateDebugStringsFromFile()
			<-ticker.C
		}
	}()
}

// shouldProcessRequest holds the filter conditions that need only method, host,
// and traffic context — no request headers. Both the legacy and the zero-copy
// fast path share it. Returns true if the request should be processed.
func shouldProcessRequest(method, host string, ctx TrafficContext) bool {
	if !IsValidMethod(method) {
		return false
	}

	if utils.IgnoreIpTraffic && utils.CheckIfIp(host) {
		return false
	}

	if utils.IgnoreCloudMetadataCalls && host == "169.254.169.254" {
		return false
	}

	if utils.IgnoreEnvoyProxycalls && ctx.SourceIP == utils.EnvoyProxyIp && ctx.Direction == utils.DirectionOutbound {
		slog.Debug("Ignoring outbound envoy proxy call", "sourceIp", ctx.SourceIP, "host", host)
		return false
	}

	return true
}

// shouldProcessRequestLegacy layers the header-map based filters (PassesFilter,
// FilterPacket) on top of the shared checks. Used by the net/http slow path,
// which already materializes a header string map.
func shouldProcessRequestLegacy(req *http.Request, reqHeaders map[string]string, ctx TrafficContext) bool {
	if !shouldProcessRequest(req.Method, req.Host, ctx) {
		return false
	}

	if !utils.PassesFilter(trafficMetrics.FilterHeaderValueMap, reqHeaders) {
		return false
	}

	if utils.FilterPacket(reqHeaders) {
		return false
	}

	return true
}

func IsValidMethod(method string) bool {
	_, ok := methodsMap[strings.ToUpper(method)]
	return ok
}

// Uses Bloom Filter + LRU Cache for memory-efficient tracking.
// Only applies optimization if memSamplingEnabled is true.
func shouldParseBody(method, host, path string) bool {
	// Only apply body parsing optimization if memory sampling is enabled
	if !memSamplingEnabled {
		return true
	}

	key := buildSignatureKey(method, host, path)

	// Step 1: Check Bloom Filter (fast, probabilistic)
	if !bloomFilter.TestString(key) {
		// Definitely first time seeing this signature
		bloomFilter.AddString(key)
		lruCache.Put(key, getTimeBucket())
		return true
	}

	// Step 2: Bloom filter says "maybe seen before" - check LRU for precise tracking
	if timeBucket, found := lruCache.Get(key); found {
		// Check if time bucket has expired
		if isTimeBucketExpired(timeBucket) {
			// More than 10 minutes since last parse
			lruCache.Put(key, getTimeBucket())
			return true
		}
		// Recently parsed, skip body
		return false
	}

	// Step 3: In Bloom but not in LRU (evicted or false positive)
	// Treat as new - parse body and add to LRU
	lruCache.Put(key, getTimeBucket())
	return true
}

// Reads /ebpf/debug-urls.txt and updates DebugStrings with any new URLs found in the file (one per line)
func UpdateDebugStringsFromFile() {
	filePath := "/ebpf/debug-urls.txt"
	f, err := os.Open(filePath)
	if err != nil {
		// File may not exist, that's fine
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	fileUrls := []string{}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			fileUrls = append(fileUrls, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return
	}

	if len(fileUrls) > 0 {
		// Merge with env DebugStrings, avoid duplicates
		urlSet := make(map[string]struct{})
		for _, u := range DebugStrings {
			urlSet[u] = struct{}{}
		}
		newUrls := []string{}
		for _, u := range fileUrls {
			if _, exists := urlSet[u]; !exists {
				newUrls = append(newUrls, u)
			}
			urlSet[u] = struct{}{}
		}
		if len(newUrls) > 0 {
			merged := make([]string, 0, len(urlSet))
			for u := range urlSet {
				merged = append(merged, u)
			}
			DebugStrings = merged
			utils.PrintLogDebug("New debugStrings found in file", "newUrls", newUrls, "DebugStrings", DebugStrings)
		}
	}
}

func checkDebugUrlAndPrint(url string, host string, message string) {
	// url or host. [array string]
	if len(DebugStrings) > 0 {
		for _, debugString := range DebugStrings {
			if strings.Contains(url, debugString) {
				ctx := context.Background()
				logMsg := fmt.Sprintf("url: %s, host: %s, message: %s", url, host, message)
				utils.PrintLogDebug(logMsg)
				go ProduceLogs(ctx, logMsg, LogTypeWarn)
				break
			} else if strings.Contains(host, debugString) {
				ctx := context.Background()
				logMsg := fmt.Sprintf("url: %s, host: %s, message: %s", url, host, message)
				utils.PrintLogDebug(logMsg)
				go ProduceLogs(ctx, logMsg, LogTypeWarn)
				break
			}
		}
	}
}

func checkAndUpdateBandwidthProcessed(sampleSize int) bool {

	if outputBandwidthLimitPerMin == -1 {
		return false
	}
	sampleMutex.Lock()
	defer sampleMutex.Unlock()
	now := time.Now().Unix()
	if int(now-lastSampleUpdate) > ONE_MINUTE {
		lastSampleUpdate = now
		currentBandwidthProcessed = 0
		slog.Debug("reset limit", "now", now, "lastSampleUpdate", lastSampleUpdate, "currentBandwidthProcessed", currentBandwidthProcessed)
	}
	skip := currentBandwidthProcessed > outputBandwidthLimitPerMin
	if !skip {
		currentBandwidthProcessed += sampleSize
		skip = currentBandwidthProcessed > outputBandwidthLimitPerMin
		if skip {
			slog.Debug("Skipping sending to akto", "now", now, "lastSampleUpdate", lastSampleUpdate, "currentBandwidthProcessed", currentBandwidthProcessed)
		}
	}
	return skip
}

func sendMetrics(headers ConvertedHeaders, ctx TrafficContext, outgoingBytes int, shouldPrint bool, responsesContent []string, i int, out []byte) {
	hostString := headers.Request.StringMap["host"]
	if utils.CheckIfIpHost(hostString) {
		hostString = "ip-host"
	}
	oc := utils.GenerateOutgoingCounter(ctx.VxlanID, ctx.SourceIP, hostString)
	trafficMetrics.SubmitOutgoingTrafficMetrics(oc, outgoingBytes)

	if shouldPrint {
		if strings.Contains(responsesContent[i], headers.DebugID) {
			goodRequests++
		} else {
			slog.Debug("req-resp.String()", "out", string(out))
			badRequests++
		}

		if goodRequests%10 == 0 || badRequests%10 == 0 {
			slog.Debug("Good requests", "count", goodRequests, "badRequests", badRequests)
		}
	}
}
