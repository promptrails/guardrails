package scanners

import (
	"context"
	"fmt"
	"strings"

	"github.com/promptrails/guardrails"
)

const wordsPerMinute = 200

// ReadingTime enforces a maximum reading time for content.
// Uses average reading speed of 200 words per minute.
type ReadingTime struct {
	maxSeconds int
}

// NewReadingTime creates a reading time scanner.
// maxSeconds is the maximum reading time in seconds.
func NewReadingTime(maxSeconds int) *ReadingTime {
	return &ReadingTime{maxSeconds: maxSeconds}
}

func (s *ReadingTime) Type() guardrails.ScannerType { return "reading_time" }

func (s *ReadingTime) Scan(_ context.Context, content string) *guardrails.Result {
	words := len(strings.Fields(content))
	seconds := (words * 60) / wordsPerMinute

	if seconds <= s.maxSeconds {
		return &guardrails.Result{Passed: true, Scanner: s.Type()}
	}

	return &guardrails.Result{
		Passed:  false,
		Scanner: s.Type(),
		Message: fmt.Sprintf("content reading time %ds exceeds limit of %ds (%d words)", seconds, s.maxSeconds, words),
	}
}
