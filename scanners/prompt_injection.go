package scanners

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/promptrails/guardrails"
)

// Common prompt injection patterns.
var injectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|above|prior)\s+(instructions?|prompts?|rules?)`),
	regexp.MustCompile(`(?i)disregard\s+(all\s+)?(previous|above|prior)\s+(instructions?|prompts?|rules?)`),
	regexp.MustCompile(`(?i)forget\s+(all\s+)?(previous|above|prior)\s+(instructions?|prompts?|rules?)`),
	regexp.MustCompile(`(?i)you\s+are\s+now\s+(a|an|the)\s+`),
	regexp.MustCompile(`(?i)new\s+instructions?:\s*`),
	regexp.MustCompile(`(?i)override\s+(system|safety|security)\s+(prompt|instructions?|rules?)`),
	regexp.MustCompile(`(?i)act\s+as\s+(if|though)\s+you`),
	regexp.MustCompile(`(?i)pretend\s+(you\s+are|to\s+be)\s+`),
	regexp.MustCompile(`(?i)jailbreak`),
	regexp.MustCompile(`(?i)DAN\s+mode`),
	regexp.MustCompile(`(?i)developer\s+mode\s+(enabled|activated|on)`),
	regexp.MustCompile(`(?i)bypass\s+(content|safety|security)\s+(filter|policy|restriction)`),
	regexp.MustCompile(`(?i)system\s*:\s*you\s+are`),
	regexp.MustCompile(`(?i)\[system\]`),
	regexp.MustCompile(`(?i)<<\s*SYS\s*>>`),
}

// PromptInjection detects common LLM prompt injection attempts using
// regex patterns. Catches override instructions, role hijacking,
// jailbreak attempts, and system prompt manipulation.
type PromptInjection struct {
	extraPatterns []*regexp.Regexp
}

// NewPromptInjection creates a prompt injection scanner with default patterns.
func NewPromptInjection() *PromptInjection {
	return &PromptInjection{}
}

// NewPromptInjectionWithPatterns creates a scanner with additional custom patterns.
// Custom patterns are checked in addition to the built-in patterns.
func NewPromptInjectionWithPatterns(patterns ...*regexp.Regexp) *PromptInjection {
	return &PromptInjection{extraPatterns: patterns}
}

func (s *PromptInjection) Type() guardrails.ScannerType { return guardrails.ScannerPromptInjection }

func (s *PromptInjection) Scan(_ context.Context, content string) *guardrails.Result {
	allPatterns := injectionPatterns
	if len(s.extraPatterns) > 0 {
		allPatterns = append(allPatterns, s.extraPatterns...)
	}

	for _, re := range allPatterns {
		if match := re.FindString(content); match != "" {
			return &guardrails.Result{
				Passed:  false,
				Scanner: guardrails.ScannerPromptInjection,
				Message: fmt.Sprintf("prompt injection detected: %q", strings.TrimSpace(match)),
				Matches: []string{match},
			}
		}
	}

	return &guardrails.Result{Passed: true, Scanner: guardrails.ScannerPromptInjection}
}
