// Package guardrails provides content safety scanning for LLM applications.
//
// It detects and optionally redacts PII, toxic content, prompt injections,
// banned substrings, and secrets in text — all locally, with zero external
// dependencies.
//
// # Quick Start
//
//	guard := guardrails.New(
//		guardrails.WithPII(),
//		guardrails.WithToxicity(),
//		guardrails.WithBanSubstrings("password", "secret"),
//	)
//
//	result := guard.Scan(ctx, "My email is alice@example.com")
//	if !result.Passed {
//		fmt.Println("Blocked:", result.Reason())
//	}
//
// # Redaction
//
//	redacted := guard.Redact(ctx, "Call me at 555-123-4567")
//	// redacted: "Call me at [PHONE_REDACTED]"
package guardrails
