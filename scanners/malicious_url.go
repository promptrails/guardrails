package scanners

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/promptrails/guardrails"
)

// Suspicious TLDs commonly used in phishing.
var suspiciousTLDs = map[string]bool{
	".tk": true, ".ml": true, ".ga": true, ".cf": true, ".gq": true,
	".xyz": true, ".top": true, ".work": true, ".click": true, ".link": true,
	".info": true, ".buzz": true, ".icu": true, ".cam": true, ".rest": true,
}

// Patterns indicating suspicious URLs.
var suspiciousPatterns = []string{
	"login", "signin", "verify", "account", "secure",
	"update", "confirm", "banking", "password", "credential",
}

// MaliciousURL detects potentially malicious URLs using heuristics:
// suspicious TLDs, IP-based hosts, excessive subdomains, and
// phishing keyword patterns.
type MaliciousURL struct {
	blockedDomains map[string]bool
}

// NewMaliciousURL creates a malicious URL scanner.
func NewMaliciousURL() *MaliciousURL {
	return &MaliciousURL{}
}

// NewMaliciousURLWithBlocklist creates a scanner with a custom domain blocklist.
func NewMaliciousURLWithBlocklist(domains ...string) *MaliciousURL {
	blocked := make(map[string]bool, len(domains))
	for _, d := range domains {
		blocked[strings.ToLower(d)] = true
	}
	return &MaliciousURL{blockedDomains: blocked}
}

func (s *MaliciousURL) Type() guardrails.ScannerType { return "malicious_url" }

func (s *MaliciousURL) Scan(_ context.Context, content string) *guardrails.Result {
	urls := urlRegex.FindAllString(content, -1)
	if len(urls) == 0 {
		return &guardrails.Result{Passed: true, Scanner: s.Type()}
	}

	var suspicious []string
	for _, rawURL := range urls {
		if reason := s.checkURL(rawURL); reason != "" {
			suspicious = append(suspicious, fmt.Sprintf("%s (%s)", rawURL, reason))
		}
	}

	if len(suspicious) == 0 {
		return &guardrails.Result{Passed: true, Scanner: s.Type()}
	}

	return &guardrails.Result{
		Passed:  false,
		Scanner: s.Type(),
		Message: fmt.Sprintf("suspicious URLs: %s", strings.Join(suspicious, "; ")),
		Matches: suspicious,
	}
}

func (s *MaliciousURL) checkURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "malformed URL"
	}

	host := strings.ToLower(parsed.Hostname())

	// Check blocklist
	if s.blockedDomains != nil && s.blockedDomains[host] {
		return "blocked domain"
	}

	// Check for IP address as host (common in phishing)
	if isIPHost(host) {
		return "IP-based URL"
	}

	// Check suspicious TLDs
	for tld := range suspiciousTLDs {
		if strings.HasSuffix(host, tld) {
			return "suspicious TLD"
		}
	}

	// Check excessive subdomains (> 3 dots)
	if strings.Count(host, ".") > 3 {
		return "excessive subdomains"
	}

	// Check for phishing keywords in path
	pathLower := strings.ToLower(parsed.Path)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(pathLower, pattern) {
			return "phishing keyword in path"
		}
	}

	return ""
}

func isIPHost(host string) bool {
	for _, r := range host {
		if r != '.' && (r < '0' || r > '9') {
			return false
		}
	}
	return len(host) > 0
}
