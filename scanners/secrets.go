package scanners

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/promptrails/guardrails"
)

// Secret patterns for common API keys and credentials.
var secretPatterns = map[string]*regexp.Regexp{
	"aws_access_key":    regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`),
	"aws_secret_key":    regexp.MustCompile(`(?i)[a-zA-Z0-9/+=]{40}`),
	"github_token":      regexp.MustCompile(`(?i)gh[pousr]_[A-Za-z0-9_]{36,}`),
	"openai_key":        regexp.MustCompile(`sk-[a-zA-Z0-9]{32,}`),
	"anthropic_key":     regexp.MustCompile(`sk-ant-[a-zA-Z0-9\-]{32,}`),
	"stripe_key":        regexp.MustCompile(`(?i)[sr]k_(live|test)_[a-zA-Z0-9]{20,}`),
	"slack_token":       regexp.MustCompile(`xox[baprs]-[a-zA-Z0-9\-]{10,}`),
	"generic_api_key":   regexp.MustCompile(`(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['\"]?[a-zA-Z0-9\-_.]{20,}['\"]?`),
	"bearer_token":      regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*`),
	"private_key":       regexp.MustCompile(`-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----`),
	"connection_string": regexp.MustCompile(`(?i)(postgres|mysql|mongodb)://[^\s]+`),
}

var secretRedactLabels = map[string]string{
	"aws_access_key":    "[AWS_KEY_REDACTED]",
	"aws_secret_key":    "[AWS_SECRET_REDACTED]",
	"github_token":      "[GITHUB_TOKEN_REDACTED]",
	"openai_key":        "[OPENAI_KEY_REDACTED]",
	"anthropic_key":     "[ANTHROPIC_KEY_REDACTED]",
	"stripe_key":        "[STRIPE_KEY_REDACTED]",
	"slack_token":       "[SLACK_TOKEN_REDACTED]",
	"generic_api_key":   "[API_KEY_REDACTED]",
	"bearer_token":      "[BEARER_TOKEN_REDACTED]",
	"private_key":       "[PRIVATE_KEY_REDACTED]",
	"connection_string": "[CONNECTION_STRING_REDACTED]",
}

// Secrets detects API keys, tokens, and credentials in text.
// Supports: AWS keys, GitHub tokens, OpenAI/Anthropic keys, Stripe keys,
// Slack tokens, generic API keys, bearer tokens, private keys, and
// database connection strings.
type Secrets struct{}

// NewSecrets creates a secrets scanner.
func NewSecrets() *Secrets {
	return &Secrets{}
}

func (s *Secrets) Type() guardrails.ScannerType { return guardrails.ScannerSecrets }

func (s *Secrets) Scan(_ context.Context, content string) *guardrails.Result {
	var detected []string

	for name, re := range secretPatterns {
		if re.MatchString(content) {
			detected = append(detected, name)
		}
	}

	if len(detected) == 0 {
		return &guardrails.Result{Passed: true, Scanner: guardrails.ScannerSecrets}
	}

	return &guardrails.Result{
		Passed:  false,
		Scanner: guardrails.ScannerSecrets,
		Message: fmt.Sprintf("secrets detected: %s", strings.Join(detected, ", ")),
		Matches: detected,
	}
}

func (s *Secrets) Redact(_ context.Context, content string) string {
	result := content
	for name, re := range secretPatterns {
		label := secretRedactLabels[name]
		result = re.ReplaceAllString(result, label)
	}
	return result
}
