package scanners

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/promptrails/guardrails"
)

// Code detection patterns.
var codePatterns = []*regexp.Regexp{
	regexp.MustCompile("(?m)^```\\w*$"),                                                 // Markdown code fences
	regexp.MustCompile(`(?m)^(def |class |import |from .+ import |async def )`),         // Python
	regexp.MustCompile(`(?m)^(function |const |let |var |=>|export )`),                  // JavaScript/TS
	regexp.MustCompile(`(?m)^(func |package |import \(|type .+ struct)`),                // Go
	regexp.MustCompile(`(?m)^(public |private |protected |class |interface )`),          // Java/C#
	regexp.MustCompile(`(?m)^(#include|using namespace|template<)`),                     // C/C++
	regexp.MustCompile(`(?m)^(SELECT |INSERT |UPDATE |DELETE |CREATE TABLE)`),           // SQL
	regexp.MustCompile(`(?m)^<\?php`),                                                   // PHP
	regexp.MustCompile(`(?m)^#!/`),                                                      // Shebang
	regexp.MustCompile(`(?m)^\s*@(app|router|controller|api)\.(get|post|put|delete)\(`), // Framework decorators
}

// BanCode detects code snippets in content using heuristic patterns.
// Catches markdown code blocks, common language keywords, and shebang lines.
type BanCode struct {
	extraPatterns []*regexp.Regexp
}

// NewBanCode creates a code detection scanner with default patterns.
func NewBanCode() *BanCode {
	return &BanCode{}
}

// NewBanCodeWithPatterns creates a scanner with additional custom patterns.
func NewBanCodeWithPatterns(patterns ...*regexp.Regexp) *BanCode {
	return &BanCode{extraPatterns: patterns}
}

func (s *BanCode) Type() guardrails.ScannerType { return "ban_code" }

func (s *BanCode) Scan(_ context.Context, content string) *guardrails.Result {
	allPatterns := codePatterns
	if len(s.extraPatterns) > 0 {
		allPatterns = append(allPatterns, s.extraPatterns...)
	}

	for _, re := range allPatterns {
		if match := re.FindString(content); match != "" {
			return &guardrails.Result{
				Passed:  false,
				Scanner: s.Type(),
				Message: fmt.Sprintf("code detected: %q", strings.TrimSpace(match)),
				Matches: []string{match},
			}
		}
	}

	return &guardrails.Result{Passed: true, Scanner: s.Type()}
}
