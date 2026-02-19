// Package scanners provides built-in content safety scanners for guardrails.
//
// Available scanners:
//   - PII: email, phone, SSN, credit card, IP address detection
//   - Toxicity: offensive language keyword matching
//   - BanSubstrings: custom banned word/phrase blocking
//   - PromptInjection: LLM prompt injection attempt detection
//   - Secrets: API key and credential detection
package scanners
