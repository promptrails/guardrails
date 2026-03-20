package scanners

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
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

func TestSentiment_Intensifiers(t *testing.T) {
	s := NewSentiment()
	result := s.Scan(context.Background(), "This is extremely terrible and absolutely horrible.")
	if result.Passed {
		t.Error("expected intensified negative to fail")
	}
}

func TestSentiment_NoSentimentWords(t *testing.T) {
	s := NewSentiment()
	result := s.Scan(context.Background(), "table chair window door")
	if !result.Passed {
		t.Error("expected text with no sentiment words to pass")
	}
}

// === BanCode Additional Tests ===

func TestBanCode_CustomPattern(t *testing.T) {
	s := NewBanCodeWithPatterns(regexp.MustCompile(`(?m)^CUSTOM_PATTERN`))
	result := s.Scan(context.Background(), "CUSTOM_PATTERN detected here")
	if result.Passed {
		t.Error("expected custom pattern detection")
	}
}

func TestBanCode_SQLDetection(t *testing.T) {
	s := NewBanCode()
	result := s.Scan(context.Background(), "SELECT * FROM users WHERE id = 1")
	if result.Passed {
		t.Error("expected SQL detection")
	}
}

func TestBanCode_ShebangDetection(t *testing.T) {
	s := NewBanCode()
	result := s.Scan(context.Background(), "#!/bin/bash\necho hello")
	if result.Passed {
		t.Error("expected shebang detection")
	}
}

// === MaliciousURL Additional Tests ===

func TestMaliciousURL_ExcessiveSubdomains(t *testing.T) {
	s := NewMaliciousURL()
	result := s.Scan(context.Background(), "Visit https://a.b.c.d.e.example.com/page")
	if result.Passed {
		t.Error("expected excessive subdomain detection")
	}
}

func TestMaliciousURL_MalformedURL(t *testing.T) {
	s := NewMaliciousURL()
	// URL regex won't match truly malformed URLs, so this should pass
	result := s.Scan(context.Background(), "not a url at all")
	if !result.Passed {
		t.Error("expected non-URL text to pass")
	}
}

// === JSONValidator Additional Tests ===

func TestJSONValidator_RequiredKeysOnArray(t *testing.T) {
	s := NewJSONValidatorWithKeys("name")
	result := s.Scan(context.Background(), `[1, 2, 3]`)
	if result.Passed {
		t.Error("expected array with required keys to fail")
	}
}

func TestJSONValidator_EmptyObject(t *testing.T) {
	s := NewJSONValidator()
	result := s.Scan(context.Background(), `{}`)
	if !result.Passed {
		t.Error("expected empty object to pass")
	}
}

// === URLReachability Additional Tests ===

func TestURLReachability_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	s := NewURLReachability()
	result := s.Scan(context.Background(), "Check "+server.URL+"/error")
	if result.Passed {
		t.Error("expected 500 error URL to fail")
	}
}

// === InvisibleText Additional Tests ===

func TestInvisibleText_MultipleInvisible(t *testing.T) {
	s := NewInvisibleText()
	// Zero-width space + zero-width non-joiner
	result := s.Scan(context.Background(), "a\u200b\u200cb")
	if result.Passed {
		t.Error("expected multiple invisible chars detection")
	}
	if len(result.Matches) < 2 {
		t.Errorf("expected at least 2 matches, got %d", len(result.Matches))
	}
}

func TestInvisibleText_Type(t *testing.T) {
	s := NewInvisibleText()
	if s.Type() != "invisible_text" {
		t.Errorf("expected type 'invisible_text', got %q", s.Type())
	}
}

// === NoRefusal Additional Tests ===

func TestNoRefusal_Type(t *testing.T) {
	s := NewNoRefusal()
	if s.Type() != "no_refusal" {
		t.Errorf("expected type 'no_refusal', got %q", s.Type())
	}
}

// === TokenLimit Additional Tests ===

func TestTokenLimit_ExactLimit(t *testing.T) {
	s := NewTokenLimit(3)
	result := s.Scan(context.Background(), "one two three")
	if !result.Passed {
		t.Error("expected exactly 3 words to pass with limit 3")
	}
}

func TestTokenLimit_Type(t *testing.T) {
	s := NewTokenLimit(10)
	if s.Type() != "token_limit" {
		t.Errorf("expected type 'token_limit', got %q", s.Type())
	}
}

// === ReadingTime Additional Tests ===

func TestReadingTime_Type(t *testing.T) {
	s := NewReadingTime(60)
	if s.Type() != "reading_time" {
		t.Errorf("expected type 'reading_time', got %q", s.Type())
	}
}

// === JSONValidator Additional Tests ===

func TestJSONValidator_Type(t *testing.T) {
	s := NewJSONValidator()
	if s.Type() != "json_validator" {
		t.Errorf("expected type 'json_validator', got %q", s.Type())
	}
}

// === BanCode Additional Tests ===

func TestBanCode_Type(t *testing.T) {
	s := NewBanCode()
	if s.Type() != "ban_code" {
		t.Errorf("expected type 'ban_code', got %q", s.Type())
	}
}

// === MaliciousURL Additional Tests ===

func TestMaliciousURL_Type(t *testing.T) {
	s := NewMaliciousURL()
	if s.Type() != "malicious_url" {
		t.Errorf("expected type 'malicious_url', got %q", s.Type())
	}
}

// === Sentiment Additional Tests ===

func TestSentiment_Type(t *testing.T) {
	s := NewSentiment()
	if s.Type() != "sentiment" {
		t.Errorf("expected type 'sentiment', got %q", s.Type())
	}
}

// === URLReachability Additional Tests ===

func TestURLReachability_Type(t *testing.T) {
	s := NewURLReachability()
	if s.Type() != "url_reachability" {
		t.Errorf("expected type 'url_reachability', got %q", s.Type())
	}
}
