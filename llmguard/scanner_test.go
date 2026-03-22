package llmguard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/promptrails/guardrails"
)

func TestScanner_Type(t *testing.T) {
	scanner := NewScanner(nil, "Toxicity", guardrails.ScannerToxicity)
	if scanner.Type() != guardrails.ScannerToxicity {
		t.Fatalf("expected type '%s', got '%s'", guardrails.ScannerToxicity, scanner.Type())
	}
}

func TestScanner_Scan(t *testing.T) {
	t.Run("passes when risk score is below default threshold", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			resp := apiResponse{
				IsValid:  true,
				Scanners: map[string]float64{"Toxicity": 0.1},
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := NewClient(server.URL, "")
		scanner := NewScanner(client, "Toxicity", guardrails.ScannerToxicity)

		result := scanner.Scan(context.Background(), "clean content")
		if !result.Passed {
			t.Fatalf("expected scan to pass, message: %s", result.Message)
		}
		if result.Scanner != guardrails.ScannerToxicity {
			t.Fatalf("expected scanner '%s', got '%s'", guardrails.ScannerToxicity, result.Scanner)
		}
	})

	t.Run("fails when risk score is above default threshold", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			resp := apiResponse{
				IsValid:  false,
				Scanners: map[string]float64{"Toxicity": 0.85},
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := NewClient(server.URL, "")
		scanner := NewScanner(client, "Toxicity", guardrails.ScannerToxicity)

		result := scanner.Scan(context.Background(), "toxic content")
		if result.Passed {
			t.Fatal("expected scan to fail for high risk score")
		}
		if result.Message == "" {
			t.Fatal("expected non-empty message")
		}
	})

	t.Run("respects custom threshold", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			resp := apiResponse{
				IsValid:  true,
				Scanners: map[string]float64{"Toxicity": 0.3},
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := NewClient(server.URL, "")
		scanner := NewScanner(client, "Toxicity", guardrails.ScannerToxicity, WithThreshold(0.2))

		result := scanner.Scan(context.Background(), "borderline content")
		if result.Passed {
			t.Fatal("expected scan to fail when score (0.3) exceeds threshold (0.2)")
		}
	})

	t.Run("passes when scanner not found in response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			resp := apiResponse{
				IsValid:  true,
				Scanners: map[string]float64{"OtherScanner": 0.1},
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := NewClient(server.URL, "")
		scanner := NewScanner(client, "Toxicity", guardrails.ScannerToxicity)

		result := scanner.Scan(context.Background(), "content")
		if !result.Passed {
			t.Fatal("expected scan to pass when scanner not in response")
		}
	})

	t.Run("returns failure on API error", func(t *testing.T) {
		client := NewClient("http://localhost:1", "")
		scanner := NewScanner(client, "Toxicity", guardrails.ScannerToxicity)

		result := scanner.Scan(context.Background(), "content")
		if result.Passed {
			t.Fatal("expected failure when API is unreachable")
		}
		if result.Message == "" {
			t.Fatal("expected error message")
		}
	})
}

func TestScanner_Redact(t *testing.T) {
	t.Run("returns sanitized content", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			resp := apiResponse{
				SanitizedPrompt: "redacted content",
				IsValid:         true,
				Scanners:        map[string]float64{"Anonymize": 0.8},
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := NewClient(server.URL, "")
		scanner := NewScanner(client, "Anonymize", guardrails.ScannerPII)

		result := scanner.Redact(context.Background(), "original content")
		if result != "redacted content" {
			t.Fatalf("expected 'redacted content', got '%s'", result)
		}
	})

	t.Run("returns original on API error", func(t *testing.T) {
		client := NewClient("http://localhost:1", "")
		scanner := NewScanner(client, "Anonymize", guardrails.ScannerPII)

		result := scanner.Redact(context.Background(), "original")
		if result != "original" {
			t.Fatalf("expected original content on error, got '%s'", result)
		}
	})
}

func TestScanner_ScanFromCached(t *testing.T) {
	scanner := NewScanner(nil, "Toxicity", guardrails.ScannerToxicity)

	t.Run("passes for low risk score", func(t *testing.T) {
		resp := &ScanResponse{
			IsValid: true,
			Results: []ScannerResult{
				{ScannerName: "Toxicity", IsValid: true, RiskScore: 0.1},
			},
		}

		result := scanner.ScanFromCached(resp)
		if !result.Passed {
			t.Fatalf("expected pass, message: %s", result.Message)
		}
	})

	t.Run("fails for high risk score", func(t *testing.T) {
		resp := &ScanResponse{
			IsValid: false,
			Results: []ScannerResult{
				{ScannerName: "Toxicity", IsValid: false, RiskScore: 0.9},
			},
		}

		result := scanner.ScanFromCached(resp)
		if result.Passed {
			t.Fatal("expected fail for high risk score")
		}
	})

	t.Run("case-insensitive scanner name matching", func(t *testing.T) {
		resp := &ScanResponse{
			Results: []ScannerResult{
				{ScannerName: "toxicity", RiskScore: 0.9},
			},
		}

		result := scanner.ScanFromCached(resp)
		if result.Passed {
			t.Fatal("expected fail — scanner name matching should be case-insensitive")
		}
	})

	t.Run("passes when scanner not in response", func(t *testing.T) {
		resp := &ScanResponse{
			Results: []ScannerResult{
				{ScannerName: "Bias", RiskScore: 0.9},
			},
		}

		result := scanner.ScanFromCached(resp)
		if !result.Passed {
			t.Fatal("expected pass when scanner not found in response")
		}
	})

	t.Run("respects custom threshold", func(t *testing.T) {
		scannerWithThreshold := NewScanner(nil, "Toxicity", guardrails.ScannerToxicity, WithThreshold(0.2))
		resp := &ScanResponse{
			Results: []ScannerResult{
				{ScannerName: "Toxicity", RiskScore: 0.3},
			},
		}

		result := scannerWithThreshold.ScanFromCached(resp)
		if result.Passed {
			t.Fatal("expected fail with custom threshold 0.2")
		}
	})
}
