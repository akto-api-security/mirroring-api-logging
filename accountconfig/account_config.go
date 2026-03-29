package accountconfig

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/akto-api-security/api-gateway-logging/trafficUtil/utils"
)

// logPrint writes to stdout, stderr, and file to ensure logs are visible
func logPrint(msg string) {
	// 1. Write to stdout
	fmt.Println(msg)
	os.Stdout.Sync()

	// 2. Write to stderr
	fmt.Fprintln(os.Stderr, msg)
	os.Stderr.Sync()

	// 3. Write to file
	if f, err := os.OpenFile("/tmp/account_config.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666); err == nil {
		fmt.Fprintln(f, msg)
		f.Close()
	}

	// 4. Write directly to /dev/stdout using raw syscall
	msg = msg + "\n"
	os.Stdout.WriteString(msg)
}

// logPrintf writes formatted output to stdout, stderr, and file
func logPrintf(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)

	// 1. Write to stdout
	fmt.Print(msg)
	os.Stdout.Sync()

	// 2. Write to stderr
	fmt.Fprint(os.Stderr, msg)
	os.Stderr.Sync()

	// 3. Write to file
	if f, err := os.OpenFile("/tmp/account_config.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666); err == nil {
		fmt.Fprint(f, msg)
		f.Close()
	}

	// 4. Write directly
	os.Stdout.WriteString(msg)
}

// AccountMapping represents a single AWS→Akto account mapping
type AccountMapping struct {
	AktoAccountId int    `json:"aktoAccountId"`
	AwsAccountId  string `json:"awsAccountId"`
	Type          string `json:"type"`
}

// AccountMappingManager manages AWS→Akto account ID mappings
type AccountMappingManager struct {
	mu                  sync.RWMutex
	awsToAktoMapping    map[string]int // awsAccountId → aktoAccountId
	cyborgBaseURL       string
	databaseAbstractorToken string
	lastFetchTime       time.Time
	fetchIntervalMinutes int
}

var globalAccountMappingManager *AccountMappingManager

// Initialize initializes the global account mapping manager
func Initialize(cyborgBaseURL, databaseAbstractorToken string, fetchIntervalMinutes int) {
	logPrint("[ACCOUNT_CONFIG] Initialize() called - setting up account mapping manager")

	globalAccountMappingManager = &AccountMappingManager{
		awsToAktoMapping:        make(map[string]int),
		cyborgBaseURL:           cyborgBaseURL,
		databaseAbstractorToken: databaseAbstractorToken,
		fetchIntervalMinutes:    fetchIntervalMinutes,
	}

	logPrint("[ACCOUNT_CONFIG] About to call FetchMappings() immediately")

	// Fetch mappings immediately on startup
	globalAccountMappingManager.FetchMappings()

	logPrint("[ACCOUNT_CONFIG] FetchMappings() completed, starting background refresh")

	// Start periodic refresh in background
	go func() {
		ticker := time.NewTicker(time.Duration(fetchIntervalMinutes) * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			globalAccountMappingManager.FetchMappings()
		}
	}()
}

// FetchMappings fetches AWS→Akto account mappings from Cyborg
func (m *AccountMappingManager) FetchMappings() {
	logPrint("[ACCOUNT_CONFIG] FetchMappings() called")

	if m.databaseAbstractorToken == "" {
		logPrint("[ACCOUNT_CONFIG] DATABASE_ABSTRACTOR_TOKEN is empty, skipping")
		utils.LogToCyborg("warn", "DATABASE_ABSTRACTOR_TOKEN not set, skipping account mapping fetch")
		return
	}
	logPrint("[ACCOUNT_CONFIG] DATABASE_ABSTRACTOR_TOKEN is set")

	client := &http.Client{Timeout: 10 * time.Second}
	url := strings.TrimRight(m.cyborgBaseURL, "/") + "/api/fetchAwsAccountIdMappings"
	logPrintf("[ACCOUNT_CONFIG] Fetching account mappings from: %s\n", url)
	utils.LogToCyborg("info", fmt.Sprintf("Fetching account mappings from: %s", url))

	// Send POST request with empty JSON body (Akto convention)
	logPrint("[ACCOUNT_CONFIG] Creating HTTP request")

	body := strings.NewReader("{}")
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		logPrintf("[ACCOUNT_CONFIG] ERROR: Failed to create request: %v\n", err)
		utils.LogToCyborg("error", fmt.Sprintf("Error creating request for account mappings: %v", err))
		return
	}
	logPrint("[ACCOUNT_CONFIG] HTTP request created successfully")

	logPrint("[ACCOUNT_CONFIG] Setting request headers...")
	req.Header.Set("Authorization", m.databaseAbstractorToken)
	logPrint("[ACCOUNT_CONFIG] Authorization header set")
	req.Header.Set("Content-Type", "application/json")
	logPrint("[ACCOUNT_CONFIG] Content-Type header set to application/json")

	logPrint("[ACCOUNT_CONFIG] Request details:")
	logPrint("[ACCOUNT_CONFIG]   Method: POST")
	logPrintf("[ACCOUNT_CONFIG]   URL: %s\n", url)
	logPrint("[ACCOUNT_CONFIG]   Body: {}")
	logPrint("[ACCOUNT_CONFIG]   Headers: Authorization=<set>, Content-Type=application/json")

	logPrint("[ACCOUNT_CONFIG] Sending HTTP request to Cyborg...")
	startTime := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(startTime)

	if err != nil {
		logPrintf("[ACCOUNT_CONFIG] ERROR: HTTP request failed after %v: %v\n", elapsed, err)
		utils.LogToCyborg("error", fmt.Sprintf("Error fetching account mappings from %s: %v", url, err))
		return
	}
	defer resp.Body.Close()

	logPrintf("[ACCOUNT_CONFIG] HTTP request completed in %v\n", elapsed)
	logPrintf("[ACCOUNT_CONFIG] Response Status Code: %d\n", resp.StatusCode)

	logPrint("[ACCOUNT_CONFIG] Response Headers:")
	for headerName, headerValues := range resp.Header {
		for _, headerValue := range headerValues {
			if headerName == "Authorization" {
				logPrintf("[ACCOUNT_CONFIG]   %s: <redacted>\n", headerName)
			} else {
				logPrintf("[ACCOUNT_CONFIG]   %s: %s\n", headerName, headerValue)
			}
		}
	}

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		respBodyStr := string(respBody)
		logPrintf("[ACCOUNT_CONFIG] ERROR: Account mapping API returned status %d\n", resp.StatusCode)
		logPrintf("[ACCOUNT_CONFIG] Response body: %s\n", respBodyStr)
		utils.LogToCyborg("error", fmt.Sprintf("Account mapping API returned %d: %s", resp.StatusCode, respBodyStr))
		return
	}

	logPrint("[ACCOUNT_CONFIG] Response status is 200 OK, parsing JSON...")

	var mappings []AccountMapping
	if err := json.NewDecoder(resp.Body).Decode(&mappings); err != nil {
		logPrintf("[ACCOUNT_CONFIG] ERROR: Failed to decode JSON response: %v\n", err)
		utils.LogToCyborg("error", fmt.Sprintf("Error decoding account mappings: %v", err))
		return
	}
	logPrint("[ACCOUNT_CONFIG] JSON response decoded successfully")

	logPrintf("[ACCOUNT_CONFIG] Received %d total mappings from Cyborg\n", len(mappings))
	utils.LogToCyborg("info", fmt.Sprintf("Received %d total mappings from Cyborg", len(mappings)))

	if len(mappings) == 0 {
		logPrint("[ACCOUNT_CONFIG] WARNING: Response contained 0 mappings")
	} else {
		logPrint("[ACCOUNT_CONFIG] Response mappings:")
		for i, m := range mappings {
			logPrintf("[ACCOUNT_CONFIG]   [%d] awsAccountId=%s, aktoAccountId=%d, type=%s\n", i, m.AwsAccountId, m.AktoAccountId, m.Type)
		}
	}

	// Update the mapping
	logPrint("[ACCOUNT_CONFIG] Acquiring lock to update mappings...")
	m.mu.Lock()
	defer m.mu.Unlock()
	logPrint("[ACCOUNT_CONFIG] Lock acquired, clearing old mappings")

	m.awsToAktoMapping = make(map[string]int)
	successCount := 0
	for _, mapping := range mappings {
		if mapping.Type == "AWS-ACCOUNTS" {
			m.awsToAktoMapping[mapping.AwsAccountId] = mapping.AktoAccountId
			successCount++
			logPrintf("[ACCOUNT_CONFIG] [SUCCESS] Mapped AWS account %s → Akto account %d\n", mapping.AwsAccountId, mapping.AktoAccountId)
			utils.LogToCyborg("info", fmt.Sprintf("Mapped AWS account %s → Akto account %d", mapping.AwsAccountId, mapping.AktoAccountId))
		} else {
			logPrintf("[ACCOUNT_CONFIG] [SKIP] Skipping mapping with type=%s (expected AWS-ACCOUNTS)\n", mapping.Type)
		}
	}
	m.lastFetchTime = time.Now()
	logPrintf("[ACCOUNT_CONFIG] Updated lastFetchTime to: %v\n", m.lastFetchTime)

	logPrint("[ACCOUNT_CONFIG] ===== FETCH COMPLETE =====")
	logPrintf("[ACCOUNT_CONFIG] Total mappings received: %d\n", len(mappings))
	logPrintf("[ACCOUNT_CONFIG] Mappings processed: %d\n", successCount)
	logPrintf("[ACCOUNT_CONFIG] Current awsToAktoMapping size: %d\n", len(m.awsToAktoMapping))
	logPrint("[ACCOUNT_CONFIG] ===== END FETCH =====")
	utils.LogToCyborg("info", fmt.Sprintf("Successfully fetched %d AWS→Akto account mappings", len(m.awsToAktoMapping)))
}

// GetAktoAccountId retrieves the Akto account ID for a given AWS account ID
// Returns the aktoAccountId if found, otherwise returns the default account ID (1000000)
func GetAktoAccountId(awsAccountId string) int {
	if globalAccountMappingManager == nil {
		return 1000000
	}

	globalAccountMappingManager.mu.RLock()
	defer globalAccountMappingManager.mu.RUnlock()

	if aktoAccountId, exists := globalAccountMappingManager.awsToAktoMapping[awsAccountId]; exists {
		return aktoAccountId
	}

	// Log when AWS account is not found in mappings (uses default)
	if awsAccountId != "" {
		utils.LogToCyborg("warn", fmt.Sprintf("AWS account ID %s not found in mappings, using default account 1000000", awsAccountId))
	}
	return 1000000
}

// GetAllMappings returns a copy of all current mappings (for debugging/monitoring)
func GetAllMappings() map[string]int {
	if globalAccountMappingManager == nil {
		return make(map[string]int)
	}

	globalAccountMappingManager.mu.RLock()
	defer globalAccountMappingManager.mu.RUnlock()

	mappingsCopy := make(map[string]int)
	for k, v := range globalAccountMappingManager.awsToAktoMapping {
		mappingsCopy[k] = v
	}
	return mappingsCopy
}

// ExtractAwsAccountIdFromLogGroupArn extracts AWS account ID from API Gateway log group ARN
// ARN format: arn:aws:logs:region:account-id:log-group:API-Gateway-Execution-Logs_...
// Returns empty string if not found
func ExtractAwsAccountIdFromLogGroupArn(logGroupArn string) string {
	// Example ARN: arn:aws:logs:us-east-1:123456789012:log-group:API-Gateway-Execution-Logs_xyz/Prod
	parts := strings.Split(logGroupArn, ":")
	if len(parts) >= 5 {
		// AWS account ID is at index 4 (0-indexed)
		accountId := parts[4]
		// Validate it's numeric
		if _, err := strconv.ParseInt(accountId, 10, 64); err == nil {
			return accountId
		}
	}
	return ""
}
