package scanners

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// === InvisibleText Tests ===

func TestInvisibleText_Detects(t *testing.T) {
	s := NewInvisibleText()
	// Zero-width space (U+200B)
	result := s.Scan(context.Background(), "hello\u200bworld")
	if result.Passed {
		t.Error("expected invisible text detection")
	}
}

func TestInvisibleText_PassesClean(t *testing.T) {
	s := NewInvisibleText()
	result := s.Scan(context.Background(), "hello world")
	if !result.Passed {
		t.Error("expected clean text to pass")
	}
}

func TestInvisibleText_Redact(t *testing.T) {
	s := NewInvisibleText()
	redacted := s.Redact(context.Background(), "hello\u200bworld")
	if redacted != "helloworld" {
		t.Errorf("expected 'helloworld', got %q", redacted)
	}
}

// === NoRefusal Tests ===

func TestNoRefusal_Detects(t *testing.T) {
	s := NewNoRefusal()
	tests := []string{
		"I'm sorry, I cannot help with that.",
		"As an AI, I don't have the ability to do that.",
		"I must decline your request.",
		"That is against my guidelines.",
	}
	for _, input := range tests {
		result := s.Scan(context.Background(), input)
		if result.Passed {
			t.Errorf("expected refusal detection for: %q", input)
		}
	}
}

func TestNoRefusal_PassesNormal(t *testing.T) {
	s := NewNoRefusal()
	result := s.Scan(context.Background(), "Here is the information you requested about quantum computing.")
	if !result.Passed {
		t.Errorf("expected normal response to pass, got: %s", result.Message)
	}
}

func TestNoRefusal_CustomPhrases(t *testing.T) {
	s := NewNoRefusalWithPhrases("no can do")
	result := s.Scan(context.Background(), "No can do, buddy.")
	if result.Passed {
		t.Error("expected custom phrase detection")
	}
}

// === TokenLimit Tests ===

func TestTokenLimit_Passes(t *testing.T) {
	s := NewTokenLimit(10)
	result := s.Scan(context.Background(), "short text here")
	if !result.Passed {
		t.Error("expected short text to pass")
	}
}

func TestTokenLimit_Blocks(t *testing.T) {
	s := NewTokenLimit(3)
	result := s.Scan(context.Background(), "this has more than three words definitely")
	if result.Passed {
		t.Error("expected long text to be blocked")
	}
}

// === ReadingTime Tests ===

func TestReadingTime_Passes(t *testing.T) {
	s := NewReadingTime(60) // 1 minute
	result := s.Scan(context.Background(), "Short text.")
	if !result.Passed {
		t.Error("expected short text to pass")
	}
}

func TestReadingTime_Blocks(t *testing.T) {
	s := NewReadingTime(1) // 1 second = ~3 words
	long := ""
	for i := 0; i < 100; i++ {
		long += "word "
	}
	result := s.Scan(context.Background(), long)
	if result.Passed {
		t.Error("expected long text to be blocked")
	}
}

// === JSONValidator Tests ===

func TestJSONValidator_ValidObject(t *testing.T) {
	s := NewJSONValidator()
	result := s.Scan(context.Background(), `{"name": "Alice", "age": 30}`)
	if !result.Passed {
		t.Error("expected valid JSON to pass")
	}
}

func TestJSONValidator_ValidArray(t *testing.T) {
	s := NewJSONValidator()
	result := s.Scan(context.Background(), `[1, 2, 3]`)
	if !result.Passed {
		t.Error("expected valid JSON array to pass")
	}
}

func TestJSONValidator_Invalid(t *testing.T) {
	s := NewJSONValidator()
	result := s.Scan(context.Background(), "not json at all")
	if result.Passed {
		t.Error("expected invalid JSON to fail")
	}
}

func TestJSONValidator_RequiredKeys(t *testing.T) {
	s := NewJSONValidatorWithKeys("name", "email")
	result := s.Scan(context.Background(), `{"name": "Alice"}`)
	if result.Passed {
		t.Error("expected missing key to fail")
	}
	if len(result.Matches) != 1 || result.Matches[0] != "email" {
		t.Errorf("expected missing 'email', got %v", result.Matches)
	}
}

func TestJSONValidator_AllKeysPresent(t *testing.T) {
	s := NewJSONValidatorWithKeys("name", "email")
	result := s.Scan(context.Background(), `{"name": "Alice", "email": "alice@example.com"}`)
	if !result.Passed {
		t.Error("expected all keys present to pass")
	}
}

// === URLReachability Tests ===

func TestURLReachability_Reachable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	s := NewURLReachability()
	result := s.Scan(context.Background(), "Check this: "+server.URL+"/page")
	if !result.Passed {
		t.Errorf("expected reachable URL to pass, got: %s", result.Message)
	}
}

func TestURLReachability_Unreachable(t *testing.T) {
	s := NewURLReachabilityWithTimeout(100 * 1e6) // 100ms
	result := s.Scan(context.Background(), "Visit http://192.0.2.1:1/nonexistent")
	if result.Passed {
		t.Error("expected unreachable URL to fail")
	}
}

func TestURLReachability_NoURLs(t *testing.T) {
	s := NewURLReachability()
	result := s.Scan(context.Background(), "no urls here")
	if !result.Passed {
		t.Error("expected no-URL text to pass")
	}
}

// === BanCode Tests ===

func TestBanCode_MarkdownFence(t *testing.T) {
	s := NewBanCode()
	result := s.Scan(context.Background(), "Here's code:\n```python\nprint('hi')\n```")
	if result.Passed {
		t.Error("expected code fence detection")
	}
}

func TestBanCode_PythonKeyword(t *testing.T) {
	s := NewBanCode()
	result := s.Scan(context.Background(), "def my_function():\n    return 42")
	if result.Passed {
		t.Error("expected Python code detection")
	}
}

func TestBanCode_GoKeyword(t *testing.T) {
	s := NewBanCode()
	result := s.Scan(context.Background(), "func main() {\n    fmt.Println(\"hello\")\n}")
	if result.Passed {
		t.Error("expected Go code detection")
	}
}

func TestBanCode_PassesNormal(t *testing.T) {
	s := NewBanCode()
	result := s.Scan(context.Background(), "This is a normal text about programming concepts.")
	if !result.Passed {
		t.Errorf("expected normal text to pass, got: %s", result.Message)
	}
}

// === MaliciousURL Tests ===

func TestMaliciousURL_SuspiciousTLD(t *testing.T) {
	s := NewMaliciousURL()
	result := s.Scan(context.Background(), "Visit https://evil-site.tk/free-money")
	if result.Passed {
		t.Error("expected suspicious TLD detection")
	}
}

func TestMaliciousURL_IPBasedURL(t *testing.T) {
	s := NewMaliciousURL()
	result := s.Scan(context.Background(), "Go to http://192.168.1.1/login")
	if result.Passed {
		t.Error("expected IP-based URL detection")
	}
}

func TestMaliciousURL_PhishingKeyword(t *testing.T) {
	s := NewMaliciousURL()
	result := s.Scan(context.Background(), "Click https://example.com/verify-account-login")
	if result.Passed {
		t.Error("expected phishing keyword detection")
	}
}

func TestMaliciousURL_BlockedDomain(t *testing.T) {
	s := NewMaliciousURLWithBlocklist("evil.com", "malware.org")
	result := s.Scan(context.Background(), "Visit https://evil.com/page")
	if result.Passed {
		t.Error("expected blocked domain detection")
	}
}

func TestMaliciousURL_PassesSafe(t *testing.T) {
	s := NewMaliciousURL()
	result := s.Scan(context.Background(), "Check https://github.com/promptrails")
	if !result.Passed {
		t.Errorf("expected safe URL to pass, got: %s", result.Message)
	}
}

func TestMaliciousURL_NoURLs(t *testing.T) {
	s := NewMaliciousURL()
	result := s.Scan(context.Background(), "no urls here")
	if !result.Passed {
		t.Error("expected no-URL text to pass")
	}
}

// === Sentiment Tests ===

func TestSentiment_Positive(t *testing.T) {
	s := NewSentiment()
	result := s.Scan(context.Background(), "This is an amazing and wonderful product! I love it!")
	if !result.Passed {
		t.Errorf("expected positive text to pass, got: %s", result.Message)
	}
}

func TestSentiment_Negative(t *testing.T) {
	s := NewSentiment()
	result := s.Scan(context.Background(), "This is terrible and horrible. Worst experience ever.")
	if result.Passed {
		t.Error("expected negative text to fail")
	}
}

func TestSentiment_Neutral(t *testing.T) {
	s := NewSentiment()
	result := s.Scan(context.Background(), "The meeting is at 3pm in the conference room.")
	if !result.Passed {
		t.Errorf("expected neutral text to pass, got: %s", result.Message)
	}
}

func TestSentiment_CustomThreshold(t *testing.T) {
	s := NewSentimentWithThreshold(-3.0) // Very tolerant
	result := s.Scan(context.Background(), "This is slightly bad.")
	if !result.Passed {
		t.Error("expected tolerant threshold to pass mildly negative text")
	}
}

func TestSentiment_Empty(t *testing.T) {
	s := NewSentiment()
	result := s.Scan(context.Background(), "")
	if !result.Passed {
		t.Error("expected empty text to pass")
	}
}
