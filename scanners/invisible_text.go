package scanners

import (
	"context"
	"fmt"
	"strings"
	"unicode"

	"github.com/promptrails/guardrails"
)

// Invisible Unicode categories used for prompt injection.
var invisibleCategories = []*unicode.RangeTable{
	unicode.Cf, // Format characters (zero-width spaces, etc.)
	unicode.Co, // Private use
}

// InvisibleText detects invisible Unicode characters that can be used
// for prompt injection attacks (zero-width spaces, format characters, etc.).
type InvisibleText struct{}

// NewInvisibleText creates an invisible text scanner.
func NewInvisibleText() *InvisibleText {
	return &InvisibleText{}
}

func (s *InvisibleText) Type() guardrails.ScannerType { return "invisible_text" }

func (s *InvisibleText) Scan(_ context.Context, content string) *guardrails.Result {
	var found []string
	for _, r := range content {
		if unicode.IsOneOf(invisibleCategories, r) {
			found = append(found, fmt.Sprintf("U+%04X", r))
		}
	}

	if len(found) == 0 {
		return &guardrails.Result{Passed: true, Scanner: s.Type()}
	}

	return &guardrails.Result{
		Passed:  false,
		Scanner: s.Type(),
		Message: fmt.Sprintf("invisible characters detected: %s", strings.Join(found, ", ")),
		Matches: found,
	}
}

func (s *InvisibleText) Redact(_ context.Context, content string) string {
	var b strings.Builder
	for _, r := range content {
		if !unicode.IsOneOf(invisibleCategories, r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}
