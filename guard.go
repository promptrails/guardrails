package guardrails

import "context"

// CheckResult is the combined result of running all scanners.
type CheckResult struct {
	// Passed is true if all scanners passed (or only log-action scanners failed).
	Passed bool

	// Results contains individual results from each scanner.
	Results []Result

	// Content is the possibly-redacted content.
	Content string

	// Redacted is true if any content was modified by redaction.
	Redacted bool
}

// Reason returns the first failure reason, or empty if all passed.
func (r *CheckResult) Reason() string {
	for _, res := range r.Results {
		if !res.Passed {
			return res.Message
		}
	}
	return ""
}

// Reasons returns all failure reasons.
func (r *CheckResult) Reasons() []string {
	var reasons []string
	for _, res := range r.Results {
		if !res.Passed {
			reasons = append(reasons, res.Message)
		}
	}
	return reasons
}

type scannerEntry struct {
	scanner Scanner
	action  Action
}

// Guard composes multiple scanners and runs them in sequence.
type Guard struct {
	entries []scannerEntry
}

// Option configures the guard.
type Option func(*Guard)

// WithScanner adds a scanner with the specified action.
func WithScanner(s Scanner, action Action) Option {
	return func(g *Guard) {
		g.addScanner(s, action)
	}
}

// New creates a new Guard with the given scanner options.
//
// Example:
//
//	guard := guardrails.New(
//		guardrails.WithScanner(scanners.NewPII(), guardrails.ActionRedact),
//		guardrails.WithScanner(scanners.NewToxicity(), guardrails.ActionBlock),
//		guardrails.WithScanner(scanners.NewPromptInjection(), guardrails.ActionBlock),
//	)
func New(opts ...Option) *Guard {
	g := &Guard{}
	for _, opt := range opts {
		opt(g)
	}
	return g
}

// addScanner registers a scanner with the given action.
func (g *Guard) addScanner(s Scanner, action Action) {
	g.entries = append(g.entries, scannerEntry{scanner: s, action: action})
}

// Scan runs all scanners on the content and returns the combined result.
// Scanners run in order. For "redact" actions, subsequent scanners see
// the redacted content.
func (g *Guard) Scan(ctx context.Context, content string) *CheckResult {
	out := &CheckResult{
		Passed:  true,
		Content: content,
	}

	for _, entry := range g.entries {
		result := entry.scanner.Scan(ctx, out.Content)
		result.Scanner = entry.scanner.Type()

		if !result.Passed {
			switch entry.action {
			case ActionBlock:
				out.Passed = false
			case ActionRedact:
				if redactor, ok := entry.scanner.(Redactor); ok {
					out.Content = redactor.Redact(ctx, out.Content)
					out.Redacted = true
				} else {
					// Scanner doesn't support redaction, treat as block
					out.Passed = false
				}
			case ActionLog:
				// Record but don't block
			}
		}

		out.Results = append(out.Results, *result)
	}

	return out
}

// Redact is a convenience method that runs all scanners with redact action
// and returns the sanitized content.
func (g *Guard) Redact(ctx context.Context, content string) string {
	current := content
	for _, entry := range g.entries {
		if redactor, ok := entry.scanner.(Redactor); ok {
			result := entry.scanner.Scan(ctx, current)
			if !result.Passed {
				current = redactor.Redact(ctx, current)
			}
		}
	}
	return current
}
