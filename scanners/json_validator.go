package scanners

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/promptrails/guardrails"
)

// JSONValidator validates that content is valid JSON.
// Optionally checks for required keys.
type JSONValidator struct {
	requiredKeys []string
}

// NewJSONValidator creates a JSON validation scanner.
func NewJSONValidator() *JSONValidator {
	return &JSONValidator{}
}

// NewJSONValidatorWithKeys creates a scanner that also checks for required keys.
func NewJSONValidatorWithKeys(keys ...string) *JSONValidator {
	return &JSONValidator{requiredKeys: keys}
}

func (s *JSONValidator) Type() guardrails.ScannerType { return "json_validator" }

func (s *JSONValidator) Scan(_ context.Context, content string) *guardrails.Result {
	trimmed := strings.TrimSpace(content)

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		// Try as array
		var arr []interface{}
		if arrErr := json.Unmarshal([]byte(trimmed), &arr); arrErr != nil {
			return &guardrails.Result{
				Passed:  false,
				Scanner: s.Type(),
				Message: fmt.Sprintf("invalid JSON: %s", err.Error()),
			}
		}
		// Valid JSON array, but can't check required keys
		if len(s.requiredKeys) > 0 {
			return &guardrails.Result{
				Passed:  false,
				Scanner: s.Type(),
				Message: "JSON is an array, expected object with required keys",
			}
		}
		return &guardrails.Result{Passed: true, Scanner: s.Type()}
	}

	// Check required keys
	var missing []string
	for _, key := range s.requiredKeys {
		if _, ok := parsed[key]; !ok {
			missing = append(missing, key)
		}
	}

	if len(missing) > 0 {
		return &guardrails.Result{
			Passed:  false,
			Scanner: s.Type(),
			Message: fmt.Sprintf("missing required JSON keys: %s", strings.Join(missing, ", ")),
			Matches: missing,
		}
	}

	return &guardrails.Result{Passed: true, Scanner: s.Type()}
}
