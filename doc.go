// Package guardrails provides content safety scanning for LLM applications.
//
// It detects and optionally redacts PII, toxic content, prompt injections,
// banned substrings, and secrets in text — all locally, with zero external
// dependencies.
//
// # Quick Start
//
//	guard := guardrails.New(
//		guardrails.WithScanner(scanners.NewPII(), guardrails.ActionRedact),
//		guardrails.WithScanner(scanners.NewToxicity(), guardrails.ActionBlock),
//		guardrails.WithScanner(scanners.NewPromptInjection(), guardrails.ActionBlock),
//	)
//
//	result := guard.Scan(ctx, "My email is alice@example.com")
//	if !result.Passed {
//		fmt.Println("Blocked:", result.Reason())
//	}
package guardrails
