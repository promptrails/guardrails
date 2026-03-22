package llmguard

import (
	"context"
	"fmt"
	"strings"

	"github.com/promptrails/guardrails"
)

// Scanner delegates scanning to LLM Guard API and maps results to the
// guardrails.Scanner interface.
type Scanner struct {
	client      *Client
	scannerName string                 // LLM Guard scanner name (e.g. "Toxicity", "PromptInjection")
	scannerType guardrails.ScannerType // guardrails scanner type constant
	threshold   float64                // risk score threshold (default 0.5)
}

// ScannerOption configures a Scanner.
type ScannerOption func(*Scanner)

// WithThreshold sets a custom risk score threshold (default 0.5).
func WithThreshold(t float64) ScannerOption {
	return func(s *Scanner) { s.threshold = t }
}

// NewScanner creates a scanner that delegates to the named LLM Guard scanner.
func NewScanner(client *Client, scannerName string, scannerType guardrails.ScannerType, opts ...ScannerOption) *Scanner {
	s := &Scanner{
		client:      client,
		scannerName: scannerName,
		scannerType: scannerType,
		threshold:   0.5,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Client returns the underlying LLM Guard client.
func (s *Scanner) Client() *Client {
	return s.client
}

// Type returns the scanner type.
func (s *Scanner) Type() guardrails.ScannerType {
	return s.scannerType
}

// Scan calls the LLM Guard API and evaluates the result for this scanner.
func (s *Scanner) Scan(ctx context.Context, content string) *guardrails.Result {
	resp, err := s.client.ScanPrompt(ctx, content)
	if err != nil {
		return &guardrails.Result{
			Passed:  false,
			Scanner: s.scannerType,
			Message: fmt.Sprintf("llmguard scanner %s: %v", s.scannerName, err),
		}
	}

	return s.evaluateResponse(resp)
}

// Redact calls LLM Guard and returns the sanitized content.
func (s *Scanner) Redact(ctx context.Context, content string) string {
	resp, err := s.client.ScanPrompt(ctx, content)
	if err != nil {
		return content
	}
	if resp.SanitizedPrompt != "" && resp.SanitizedPrompt != content {
		return resp.SanitizedPrompt
	}
	return content
}

// ScanFromCached evaluates a pre-fetched ScanResponse against this scanner's threshold.
// Used for batch scanning to avoid per-scanner API calls.
func (s *Scanner) ScanFromCached(resp *ScanResponse) *guardrails.Result {
	return s.evaluateResponse(resp)
}

func (s *Scanner) evaluateResponse(resp *ScanResponse) *guardrails.Result {
	for _, r := range resp.Results {
		if strings.EqualFold(r.ScannerName, s.scannerName) {
			if r.RiskScore >= s.threshold {
				return &guardrails.Result{
					Passed:  false,
					Scanner: s.scannerType,
					Message: fmt.Sprintf("%s detected (risk_score: %.2f, threshold: %.2f)", s.scannerName, r.RiskScore, s.threshold),
				}
			}
			return &guardrails.Result{
				Passed:  true,
				Scanner: s.scannerType,
			}
		}
	}

	// Scanner not found in response — pass by default
	return &guardrails.Result{Passed: true, Scanner: s.scannerType}
}
