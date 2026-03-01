package scanners

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/promptrails/guardrails"
)

// PII regex patterns.
var (
	emailRegex      = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	phoneRegex      = regexp.MustCompile(`(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}`)
	ssnRegex        = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	creditCardRegex = regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)
	ipAddressRegex  = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
)

var piiPatterns = map[string]*regexp.Regexp{
	"email":       emailRegex,
	"phone":       phoneRegex,
	"ssn":         ssnRegex,
	"credit_card": creditCardRegex,
	"ip_address":  ipAddressRegex,
}

var piiRedactLabels = map[string]string{ // #nosec G101 -- redaction labels, not credentials
	"email":       "[EMAIL_REDACTED]",
	"phone":       "[PHONE_REDACTED]",
	"ssn":         "[SSN_REDACTED]",
	"credit_card": "[CARD_REDACTED]",
	"ip_address":  "[IP_REDACTED]",
}

// PII detects personally identifiable information using regex patterns.
// Supports: email, phone, SSN, credit card, IP address.
// Implements both Scanner and Redactor.
type PII struct {
	types []string
}

// NewPII creates a PII scanner that checks all PII types.
func NewPII() *PII {
	return &PII{}
}

// NewPIIWithTypes creates a PII scanner that checks only the specified types.
// Valid types: "email", "phone", "ssn", "credit_card", "ip_address".
func NewPIIWithTypes(types ...string) *PII {
	return &PII{types: types}
}

func (s *PII) Type() guardrails.ScannerType { return guardrails.ScannerPII }

func (s *PII) Scan(_ context.Context, content string) *guardrails.Result {
	patterns := s.activePatterns()

	var detected []string
	for name, re := range patterns {
		if re.MatchString(content) {
			detected = append(detected, name)
		}
	}

	if len(detected) == 0 {
		return &guardrails.Result{Passed: true, Scanner: guardrails.ScannerPII}
	}

	return &guardrails.Result{
		Passed:  false,
		Scanner: guardrails.ScannerPII,
		Message: fmt.Sprintf("PII detected: %s", strings.Join(detected, ", ")),
		Matches: detected,
	}
}

func (s *PII) Redact(_ context.Context, content string) string {
	patterns := s.activePatterns()
	result := content
	for name, re := range patterns {
		label := piiRedactLabels[name]
		result = re.ReplaceAllString(result, label)
	}
	return result
}

func (s *PII) activePatterns() map[string]*regexp.Regexp {
	if len(s.types) == 0 {
		return piiPatterns
	}
	active := make(map[string]*regexp.Regexp)
	for _, t := range s.types {
		if re, ok := piiPatterns[t]; ok {
			active[t] = re
		}
	}
	return active
}
