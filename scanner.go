package guardrails

import "context"

// Action defines what to do when a scanner detects a violation.
type Action string

const (
	// ActionBlock stops processing and returns an error.
	ActionBlock Action = "block"

	// ActionRedact sanitizes the content and continues.
	ActionRedact Action = "redact"

	// ActionLog records the violation but continues unchanged.
	ActionLog Action = "log"
)

// ScannerType identifies a scanner.
type ScannerType string

const (
	ScannerPII             ScannerType = "pii"
	ScannerToxicity        ScannerType = "toxicity"
	ScannerBanSubstrings   ScannerType = "ban_substrings"
	ScannerPromptInjection ScannerType = "prompt_injection"
	ScannerSecrets         ScannerType = "secrets"
)

// Scanner checks content for violations.
type Scanner interface {
	// Scan checks the content and returns a result.
	Scan(ctx context.Context, content string) *Result

	// Type returns the scanner type identifier.
	Type() ScannerType
}

// Redactor can sanitize content by replacing detected violations.
type Redactor interface {
	// Redact returns the content with violations replaced.
	Redact(ctx context.Context, content string) string
}

// Result represents the outcome of a single scan.
type Result struct {
	// Passed is true if no violation was detected.
	Passed bool

	// Scanner is the type of scanner that produced this result.
	Scanner ScannerType

	// Message describes the violation. Empty if Passed is true.
	Message string

	// Matches contains the specific strings that triggered the scanner.
	Matches []string
}
