package utils

import (
	"github.com/akto-api-security/mirroring-api-logging/utils"
	"testing"
)

func TestParseInjectTags(t *testing.T) {
	tests := []struct {
		env  string
		want string
	}{
		{"", ""},
		{"env=prod", `{"env":"prod"}`},
		{"env=prod;team=payments", `{"env":"prod","team":"payments"}`},
		{" env = prod ; team=payments ;", `{"env":"prod","team":"payments"}`},
		{"url=a=b", `{"url":"a=b"}`},
		{"empty=", `{"empty":""}`},
		{"env=dev;env=prod", `{"env":"prod"}`},
		{"novalue;=nokey; =blank", ""},
		{`quote="x"`, `{"quote":"\"x\""}`},
	}

	for _, tt := range tests {
		if got := utils.ParseInjectTags(tt.env); got != tt.want {
			t.Errorf("ParseInjectTags(%q) = %q, want %q", tt.env, got, tt.want)
		}
	}
}
