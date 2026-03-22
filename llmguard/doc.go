// Package llmguard provides an HTTP client and scanner adapter for the
// LLM Guard API (https://llm-guard.com).
//
// # Client Usage
//
//	client := llmguard.NewClient("http://localhost:8000", "optional-token")
//	resp, err := client.ScanPrompt(ctx, "user input")
//	for _, r := range resp.Results {
//	    fmt.Printf("%s: risk=%.2f valid=%v\n", r.ScannerName, r.RiskScore, r.IsValid)
//	}
//
// # As a guardrails.Scanner
//
//	scanner := llmguard.NewScanner(client, "Toxicity", guardrails.ScannerToxicity)
//	result := scanner.Scan(ctx, "some content")
//	if !result.Passed {
//	    fmt.Println(result.Message)
//	}
package llmguard
