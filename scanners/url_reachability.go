package scanners

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/promptrails/guardrails"
)

var urlRegex = regexp.MustCompile(`https?://[^\s<>\"\')]+`)

// URLReachability checks that URLs in content are reachable via HTTP HEAD.
// Useful for detecting hallucinated URLs in LLM output.
type URLReachability struct {
	timeout time.Duration
	client  *http.Client
}

// NewURLReachability creates a URL reachability scanner with a 5-second timeout.
func NewURLReachability() *URLReachability {
	return &URLReachability{timeout: 5 * time.Second}
}

// NewURLReachabilityWithTimeout creates a scanner with a custom timeout per URL.
func NewURLReachabilityWithTimeout(timeout time.Duration) *URLReachability {
	return &URLReachability{timeout: timeout}
}

func (s *URLReachability) Type() guardrails.ScannerType { return "url_reachability" }

func (s *URLReachability) Scan(ctx context.Context, content string) *guardrails.Result {
	urls := urlRegex.FindAllString(content, -1)
	if len(urls) == 0 {
		return &guardrails.Result{Passed: true, Scanner: s.Type()}
	}

	client := s.client
	if client == nil {
		client = &http.Client{Timeout: s.timeout}
	}

	var unreachable []string
	for _, u := range urls {
		if !s.isReachable(ctx, client, u) {
			unreachable = append(unreachable, u)
		}
	}

	if len(unreachable) == 0 {
		return &guardrails.Result{Passed: true, Scanner: s.Type()}
	}

	return &guardrails.Result{
		Passed:  false,
		Scanner: s.Type(),
		Message: fmt.Sprintf("unreachable URLs: %s", strings.Join(unreachable, ", ")),
		Matches: unreachable,
	}
}

func (s *URLReachability) isReachable(ctx context.Context, client *http.Client, url string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()

	return resp.StatusCode < 400
}
