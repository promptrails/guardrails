package llmguard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is an HTTP client for the LLM Guard API.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// ClientOption configures a Client.
type ClientOption func(*Client)

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(c *http.Client) ClientOption {
	return func(cl *Client) { cl.httpClient = c }
}

// NewClient creates a new LLM Guard API client.
func NewClient(baseURL, token string, opts ...ClientOption) *Client {
	c := &Client{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// ScannerResult holds a single scanner's result from LLM Guard.
type ScannerResult struct {
	ScannerName string  `json:"scanner_name"`
	IsValid     bool    `json:"is_valid"`
	RiskScore   float64 `json:"risk_score"`
}

// ScanResponse is the parsed response from LLM Guard API.
type ScanResponse struct {
	SanitizedPrompt string          `json:"sanitized_prompt"`
	SanitizedOutput string          `json:"sanitized_output"`
	Results         []ScannerResult `json:"results"`
	IsValid         bool            `json:"is_valid"`
}

// promptRequest is the request body for /analyze/prompt.
type promptRequest struct {
	Prompt string `json:"prompt"`
}

// outputRequest is the request body for /analyze/output.
type outputRequest struct {
	Prompt string `json:"prompt"`
	Output string `json:"output"`
}

// apiResponse is the raw API response from LLM Guard.
type apiResponse struct {
	SanitizedPrompt string             `json:"sanitized_prompt"`
	SanitizedOutput string             `json:"sanitized_output"`
	IsValid         bool               `json:"is_valid"`
	Scanners        map[string]float64 `json:"scanners"`
}

// ScanPrompt calls POST /analyze/prompt on the LLM Guard API.
func (c *Client) ScanPrompt(ctx context.Context, prompt string) (*ScanResponse, error) {
	body, err := json.Marshal(promptRequest{Prompt: prompt})
	if err != nil {
		return nil, fmt.Errorf("llmguard: marshal request: %w", err)
	}
	return c.doAndParse(ctx, "/analyze/prompt", body)
}

// ScanOutput calls POST /analyze/output on the LLM Guard API.
func (c *Client) ScanOutput(ctx context.Context, prompt, output string) (*ScanResponse, error) {
	body, err := json.Marshal(outputRequest{Prompt: prompt, Output: output})
	if err != nil {
		return nil, fmt.Errorf("llmguard: marshal request: %w", err)
	}
	return c.doAndParse(ctx, "/analyze/output", body)
}

func (c *Client) doAndParse(ctx context.Context, path string, body []byte) (*ScanResponse, error) {
	respBody, err := c.doRequest(ctx, path, body)
	if err != nil {
		return nil, err
	}
	return c.parseResponse(respBody)
}

func (c *Client) doRequest(ctx context.Context, path string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("llmguard: create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("llmguard: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("llmguard: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("llmguard: unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

func (c *Client) parseResponse(body []byte) (*ScanResponse, error) {
	var raw apiResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("llmguard: unmarshal response: %w", err)
	}

	result := &ScanResponse{
		SanitizedPrompt: raw.SanitizedPrompt,
		SanitizedOutput: raw.SanitizedOutput,
		IsValid:         raw.IsValid,
	}

	for scannerName, riskScore := range raw.Scanners {
		result.Results = append(result.Results, ScannerResult{
			ScannerName: scannerName,
			IsValid:     riskScore < 0.5,
			RiskScore:   riskScore,
		})
	}

	return result, nil
}
