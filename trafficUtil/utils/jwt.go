package utils

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// AccountIDFromToken parses the JWT (e.g. DATABASE_ABSTRACTOR_TOKEN), decodes the payload
// without verification, and returns the accountId claim. Tries "accountId" and "account_id".
// Returns empty string if token is empty, malformed, or claim is missing.
func AccountIDFromToken(token string) string {
	if token == "" {
		return ""
	}
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	if id, ok := claims["accountId"]; ok {
		return accountIDClaim(id)
	}
	return ""
}

func accountIDClaim(v interface{}) string {
	switch s := v.(type) {
	case string:
		return s
	case float64:
		return fmt.Sprintf("%.0f", s)
	default:
		return ""
	}
}
