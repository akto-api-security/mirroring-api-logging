package logprocesser

import (
	"reflect"
	"testing"
)

const testLogGroupArn = "arn:aws:logs:us-east-1:123456789012:log-group:API-Gateway-Execution-Logs_abc123/prod"

func TestEnsureHostHeader(t *testing.T) {
	tests := []struct {
		name      string
		logLine   string
		logGroup  string
		wantHosts map[string]string
	}{
		{
			name:      "complete host is kept",
			logLine:   "(req-1) Method request headers: {Accept=*/*, Host=subs.example.com}",
			logGroup:  testLogGroupArn,
			wantHosts: map[string]string{"Host": "subs.example.com"},
		},
		{
			name:      "lowercase complete host is kept",
			logLine:   "(req-1) Method request headers: {accept=*/*, host=subs.example.com}",
			logGroup:  testLogGroupArn,
			wantHosts: map[string]string{"host": "subs.example.com"},
		},
		{
			name:      "truncated host value is replaced",
			logLine:   "(req-1) Method request headers: {Accept=*/*, Host=subs [TRUNCATED]",
			logGroup:  testLogGroupArn,
			wantHosts: map[string]string{"Host": "abc123.prod"},
		},
		{
			name:      "truncated lowercase host is replaced without duplicates",
			logLine:   "(req-1) Method request headers: {accept=*/*, host=subs [TRUNCATED]",
			logGroup:  testLogGroupArn,
			wantHosts: map[string]string{"Host": "abc123.prod"},
		},
		{
			name:      "truncation inside header name is treated as missing",
			logLine:   "(req-1) Method request headers: {Accept=*/*, Ho [TRUNCATED]",
			logGroup:  testLogGroupArn,
			wantHosts: map[string]string{"Host": "abc123.prod"},
		},
		{
			name:      "missing host is added",
			logLine:   "(req-1) Method request headers: {Accept=*/*}",
			logGroup:  testLogGroupArn,
			wantHosts: map[string]string{"Host": "abc123.prod"},
		},
		{
			name:      "truncated host kept when log group gives no host",
			logLine:   "(req-1) Method request headers: {Accept=*/*, Host=subs [TRUNCATED]",
			logGroup:  "",
			wantHosts: map[string]string{"Host": "subs [TRUNCATED]"},
		},
		{
			name:      "truncation on another header leaves host alone",
			logLine:   "(req-1) Method request headers: {Host=subs.example.com, User-Agent=Mozi [TRUNCATED]",
			logGroup:  testLogGroupArn,
			wantHosts: map[string]string{"Host": "subs.example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := extractMap(tt.logLine, "Method request headers:")
			ensureHostHeader(headers, tt.logGroup)

			gotHosts := map[string]string{}
			for k, v := range headers {
				if k == "Host" || k == "host" || k == "HOST" {
					gotHosts[k] = v
				}
			}
			if !reflect.DeepEqual(gotHosts, tt.wantHosts) {
				t.Errorf("host headers = %v, want %v (all headers: %v)", gotHosts, tt.wantHosts, headers)
			}
		})
	}
}
