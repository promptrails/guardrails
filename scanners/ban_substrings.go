package scanners

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/promptrails/guardrails"
)

// BanSubstrings blocks content containing any of the specified substrings.
// Case-insensitive matching. Supports redaction by replacing matches with [REDACTED].
type BanSubstrings struct {
	substrings []string
}

// NewBanSubstrings creates a scanner that blocks the specified substrings.
func NewBanSubstrings(substrings ...string) *BanSubstrings {
	return &BanSubstrings{substrings: substrings}
}

func (s *BanSubstrings) Type() guardrails.ScannerType { return guardrails.ScannerBanSubstrings }

func (s *BanSubstrings) Scan(_ context.Context, content string) *guardrails.Result {
	lower := strings.ToLower(content)

	for _, sub := range s.substrings {
		if strings.Contains(lower, strings.ToLower(sub)) {
			return &guardrails.Result{
				Passed:  false,
				Scanner: guardrails.ScannerBanSubstrings,
				Message: fmt.Sprintf("content contains banned substring: %q", sub),
				Matches: []string{sub},
			}
		}
	}

	return &guardrails.Result{Passed: true, Scanner: guardrails.ScannerBanSubstrings}
}

func (s *BanSubstrings) Redact(_ context.Context, content string) string {
	result := content
	for _, sub := range s.substrings {
		re := regexp.MustCompile("(?i)" + regexp.QuoteMeta(sub))
		result = re.ReplaceAllString(result, "[REDACTED]")
	}
	return result
}
