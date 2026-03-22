package llmguard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_ScanPrompt(t *testing.T) {
	t.Run("parses successful response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/analyze/prompt" {
				t.Fatalf("expected path /analyze/prompt, got %s", r.URL.Path)
			}
			if r.Method != http.MethodPost {
				t.Fatalf("expected POST, got %s", r.Method)
			}
			if r.Header.Get("Content-Type") != "application/json" {
				t.Fatalf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
			}

			var req promptRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("failed to decode request body: %v", err)
			}
			if req.Prompt != "test prompt" {
				t.Fatalf("expected prompt 'test prompt', got '%s'", req.Prompt)
			}

			resp := apiResponse{
				SanitizedPrompt: "test prompt",
				IsValid:         true,
				Scanners: map[string]float64{
					"Toxicity":        0.1,
					"PromptInjection": 0.05,
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := NewClient(server.URL, "")
		result, err := client.ScanPrompt(context.Background(), "test prompt")
		if err != nil {
			t.Fatalf("ScanPrompt returned error: %v", err)
		}

		if !result.IsValid {
			t.Fatal("expected IsValid to be true")
		}
		if result.SanitizedPrompt != "test prompt" {
			t.Fatalf("expected sanitized prompt 'test prompt', got '%s'", result.SanitizedPrompt)
		}
		if len(result.Results) != 2 {
			t.Fatalf("expected 2 scanner results, got %d", len(result.Results))
		}

		found := false
		for _, r := range result.Results {
			if r.ScannerName == "Toxicity" {
				found = true
				if r.RiskScore != 0.1 {
					t.Fatalf("expected Toxicity risk score 0.1, got %f", r.RiskScore)
				}
				if !r.IsValid {
					t.Fatal("expected Toxicity IsValid to be true (score < 0.5)")
				}
			}
		}
		if !found {
			t.Fatal("Toxicity scanner result not found")
		}
	})

	t.Run("sends authorization header when token is set", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader != "Bearer test-token" {
				t.Fatalf("expected Authorization 'Bearer test-token', got '%s'", authHeader)
			}

			resp := apiResponse{IsValid: true, Scanners: map[string]float64{}}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := NewClient(server.URL, "test-token")
		_, err := client.ScanPrompt(context.Background(), "test")
		if err != nil {
			t.Fatalf("ScanPrompt returned error: %v", err)
		}
	})

	t.Run("does not send authorization header when token is empty", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" {
				t.Fatalf("expected no Authorization header, got '%s'", authHeader)
			}

			resp := apiResponse{IsValid: true, Scanners: map[string]float64{}}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := NewClient(server.URL, "")
		_, err := client.ScanPrompt(context.Background(), "test")
		if err != nil {
			t.Fatalf("ScanPrompt returned error: %v", err)
		}
	})

	t.Run("returns error on non-200 status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("internal error"))
		}))
		defer server.Close()

		client := NewClient(server.URL, "")
		_, err := client.ScanPrompt(context.Background(), "test")
		if err == nil {
			t.Fatal("expected error for 500 status")
		}
	})

	t.Run("returns error on connection failure", func(t *testing.T) {
		client := NewClient("http://localhost:1", "")
		_, err := client.ScanPrompt(context.Background(), "test")
		if err == nil {
			t.Fatal("expected error for connection failure")
		}
	})

	t.Run("returns error on invalid JSON response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("not json"))
		}))
		defer server.Close()

		client := NewClient(server.URL, "")
		_, err := client.ScanPrompt(context.Background(), "test")
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})

	t.Run("high risk score marks result as invalid", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			resp := apiResponse{
				IsValid:  false,
				Scanners: map[string]float64{"Toxicity": 0.9},
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := NewClient(server.URL, "")
		result, err := client.ScanPrompt(context.Background(), "toxic content")
		if err != nil {
			t.Fatalf("ScanPrompt returned error: %v", err)
		}

		if result.IsValid {
			t.Fatal("expected IsValid to be false")
		}
		for _, r := range result.Results {
			if r.ScannerName == "Toxicity" && r.IsValid {
				t.Fatal("expected Toxicity to be invalid (score >= 0.5)")
			}
		}
	})
}

func TestClient_ScanOutput(t *testing.T) {
	t.Run("sends prompt and output in request body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/analyze/output" {
				t.Fatalf("expected path /analyze/output, got %s", r.URL.Path)
			}

			var req outputRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("failed to decode request body: %v", err)
			}
			if req.Prompt != "original prompt" {
				t.Fatalf("expected prompt 'original prompt', got '%s'", req.Prompt)
			}
			if req.Output != "llm response" {
				t.Fatalf("expected output 'llm response', got '%s'", req.Output)
			}

			resp := apiResponse{
				SanitizedOutput: "llm response",
				IsValid:         true,
				Scanners:        map[string]float64{"Bias": 0.2},
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := NewClient(server.URL, "")
		result, err := client.ScanOutput(context.Background(), "original prompt", "llm response")
		if err != nil {
			t.Fatalf("ScanOutput returned error: %v", err)
		}

		if !result.IsValid {
			t.Fatal("expected IsValid to be true")
		}
		if result.SanitizedOutput != "llm response" {
			t.Fatalf("expected sanitized output 'llm response', got '%s'", result.SanitizedOutput)
		}
	})
}
