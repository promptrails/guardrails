package guardrails

import (
	"context"
	"testing"
)

type passingScanner struct{}

func (s *passingScanner) Type() ScannerType                        { return "test_pass" }
func (s *passingScanner) Scan(_ context.Context, _ string) *Result { return &Result{Passed: true} }

type failingScanner struct{}

func (s *failingScanner) Type() ScannerType { return "test_fail" }
func (s *failingScanner) Scan(_ context.Context, _ string) *Result {
	return &Result{Passed: false, Message: "test failure"}
}

type redactingScanner struct{}

func (s *redactingScanner) Type() ScannerType { return "test_redact" }
func (s *redactingScanner) Scan(_ context.Context, _ string) *Result {
	return &Result{Passed: false, Message: "needs redaction"}
}
func (s *redactingScanner) Redact(_ context.Context, content string) string {
	return "[REDACTED]"
}

func TestGuard_AllPass(t *testing.T) {
	guard := New(
		WithScanner(&passingScanner{}, ActionBlock),
		WithScanner(&passingScanner{}, ActionBlock),
	)

	result := guard.Scan(context.Background(), "hello world")
	if !result.Passed {
		t.Error("expected all scanners to pass")
	}
	if len(result.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(result.Results))
	}
}

func TestGuard_BlockAction(t *testing.T) {
	guard := New(WithScanner(&failingScanner{}, ActionBlock))

	result := guard.Scan(context.Background(), "bad content")
	if result.Passed {
		t.Error("expected block")
	}
	if result.Reason() != "test failure" {
		t.Errorf("expected reason 'test failure', got %q", result.Reason())
	}
}

func TestGuard_RedactAction(t *testing.T) {
	guard := New(WithScanner(&redactingScanner{}, ActionRedact))

	result := guard.Scan(context.Background(), "sensitive data")
	if !result.Passed {
		t.Error("redact action should not block")
	}
	if !result.Redacted {
		t.Error("expected redacted flag")
	}
	if result.Content != "[REDACTED]" {
		t.Errorf("expected redacted content, got %q", result.Content)
	}
}

func TestGuard_LogAction(t *testing.T) {
	guard := New(WithScanner(&failingScanner{}, ActionLog))

	result := guard.Scan(context.Background(), "content")
	if !result.Passed {
		t.Error("log action should not block")
	}
	if len(result.Results) != 1 || result.Results[0].Passed {
		t.Error("expected failed result recorded")
	}
}

func TestGuard_RedactWithoutRedactor(t *testing.T) {
	// failingScanner doesn't implement Redactor
	guard := New(WithScanner(&failingScanner{}, ActionRedact))

	result := guard.Scan(context.Background(), "content")
	if result.Passed {
		t.Error("expected block when scanner can't redact")
	}
}

func TestGuard_ChainedRedaction(t *testing.T) {
	guard := New(
		WithScanner(&redactingScanner{}, ActionRedact),
		WithScanner(&passingScanner{}, ActionBlock),
	)

	result := guard.Scan(context.Background(), "original")
	if result.Content != "[REDACTED]" {
		t.Errorf("expected chained redaction, got %q", result.Content)
	}
}

func TestGuard_RedactMethod(t *testing.T) {
	guard := New(WithScanner(&redactingScanner{}, ActionRedact))

	result := guard.Redact(context.Background(), "sensitive")
	if result != "[REDACTED]" {
		t.Errorf("expected '[REDACTED]', got %q", result)
	}
}

func TestCheckResult_Reasons(t *testing.T) {
	r := &CheckResult{
		Results: []Result{
			{Passed: true},
			{Passed: false, Message: "reason 1"},
			{Passed: false, Message: "reason 2"},
		},
	}

	reasons := r.Reasons()
	if len(reasons) != 2 {
		t.Fatalf("expected 2 reasons, got %d", len(reasons))
	}
	if reasons[0] != "reason 1" {
		t.Errorf("expected 'reason 1', got %q", reasons[0])
	}
}

func TestCheckResult_Reason_AllPassed(t *testing.T) {
	r := &CheckResult{
		Results: []Result{{Passed: true}, {Passed: true}},
	}
	if r.Reason() != "" {
		t.Errorf("expected empty reason, got %q", r.Reason())
	}
}
