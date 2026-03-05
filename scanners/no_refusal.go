package scanners

import (
	"context"
	"fmt"
	"strings"

	"github.com/promptrails/guardrails"
)

// Common LLM refusal phrases.
var defaultRefusalPhrases = []string{
	"i'm sorry",
	"i cannot",
	"i can't",
	"i am not able to",
	"i'm not able to",
	"as an ai",
	"as a language model",
	"as an artificial intelligence",
	"i don't have the ability",
	"i'm unable to",
	"i am unable to",
	"it is not appropriate",
	"it's not appropriate",
	"i'm not allowed",
	"i am not allowed",
	"i must decline",
	"i have to decline",
	"i cannot comply",
	"i can't comply",
	"against my guidelines",
	"against my programming",
	"i'm designed to",
	"my purpose is to",
	"i'm programmed to",
	"not within my capabilities",
}

// NoRefusal detects when an LLM refuses to answer using known refusal phrases.
// Useful for detecting over-cautious model behavior.
type NoRefusal struct {
	phrases []string
}

// NewNoRefusal creates a no-refusal scanner with default phrases.
func NewNoRefusal() *NoRefusal {
	return &NoRefusal{phrases: defaultRefusalPhrases}
}

// NewNoRefusalWithPhrases creates a scanner with custom refusal phrases.
func NewNoRefusalWithPhrases(phrases ...string) *NoRefusal {
	return &NoRefusal{phrases: phrases}
}

func (s *NoRefusal) Type() guardrails.ScannerType { return "no_refusal" }

func (s *NoRefusal) Scan(_ context.Context, content string) *guardrails.Result {
	lower := strings.ToLower(content)

	for _, phrase := range s.phrases {
		if strings.Contains(lower, phrase) {
			return &guardrails.Result{
				Passed:  false,
				Scanner: s.Type(),
				Message: fmt.Sprintf("LLM refusal detected: matched phrase %q", phrase),
				Matches: []string{phrase},
			}
		}
	}

	return &guardrails.Result{Passed: true, Scanner: s.Type()}
}
