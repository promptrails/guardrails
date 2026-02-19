package scanners

import (
	"context"
	"fmt"
	"strings"

	"github.com/promptrails/guardrails"
)

// Default toxic words.
var defaultToxicWords = []string{
	"kill", "murder", "hate", "racist", "sexist",
	"slur", "violence", "abuse", "harass", "threat",
}

// Toxicity detects offensive or harmful language using keyword matching.
// Case-insensitive. Uses a default word list that can be replaced.
type Toxicity struct {
	words []string
}

// NewToxicity creates a toxicity scanner with the default word list.
func NewToxicity() *Toxicity {
	return &Toxicity{words: defaultToxicWords}
}

// NewToxicityWithWords creates a toxicity scanner with a custom word list.
func NewToxicityWithWords(words ...string) *Toxicity {
	return &Toxicity{words: words}
}

func (s *Toxicity) Type() guardrails.ScannerType { return guardrails.ScannerToxicity }

func (s *Toxicity) Scan(_ context.Context, content string) *guardrails.Result {
	lower := strings.ToLower(content)

	for _, word := range s.words {
		if strings.Contains(lower, strings.ToLower(word)) {
			return &guardrails.Result{
				Passed:  false,
				Scanner: guardrails.ScannerToxicity,
				Message: fmt.Sprintf("toxic content detected: matched word '%s'", word),
				Matches: []string{word},
			}
		}
	}

	return &guardrails.Result{Passed: true, Scanner: guardrails.ScannerToxicity}
}
