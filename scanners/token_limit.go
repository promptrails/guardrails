package scanners

import (
	"context"
	"fmt"
	"strings"

	"github.com/promptrails/guardrails"
)

// TokenLimit enforces a maximum word count on content.
// Uses word count as a proxy for tokens (~0.75 tokens per word).
type TokenLimit struct {
	maxWords int
}

// NewTokenLimit creates a token limit scanner.
// maxWords is the maximum number of words allowed.
func NewTokenLimit(maxWords int) *TokenLimit {
	return &TokenLimit{maxWords: maxWords}
}

func (s *TokenLimit) Type() guardrails.ScannerType { return "token_limit" }

func (s *TokenLimit) Scan(_ context.Context, content string) *guardrails.Result {
	words := len(strings.Fields(content))

	if words <= s.maxWords {
		return &guardrails.Result{Passed: true, Scanner: s.Type()}
	}

	return &guardrails.Result{
		Passed:  false,
		Scanner: s.Type(),
		Message: fmt.Sprintf("content exceeds word limit: %d words (max %d)", words, s.maxWords),
	}
}
