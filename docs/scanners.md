# Scanners

## PII

Detects personally identifiable information using regex patterns.

```go
// Detect all PII types
s := scanners.NewPII()

// Detect specific types only
s := scanners.NewPIIWithTypes("email", "phone")
```

**Supported types**: `email`, `phone`, `ssn`, `credit_card`, `ip_address`

**Redaction labels**:

| Type | Redacted As |
|------|-------------|
| email | `[EMAIL_REDACTED]` |
| phone | `[PHONE_REDACTED]` |
| ssn | `[SSN_REDACTED]` |
| credit_card | `[CARD_REDACTED]` |
| ip_address | `[IP_REDACTED]` |

**Implements**: `Scanner`, `Redactor`

## Toxicity

Detects offensive or harmful language using keyword matching. Case-insensitive.

```go
// Default word list
s := scanners.NewToxicity()

// Custom word list (replaces defaults)
s := scanners.NewToxicityWithWords("forbidden", "banned", "inappropriate")
```

**Default words**: kill, murder, hate, racist, sexist, slur, violence, abuse, harass, threat

**Implements**: `Scanner`

## BanSubstrings

Blocks content containing any of the specified substrings. Case-insensitive.

```go
s := scanners.NewBanSubstrings("password", "secret", "confidential")
```

Supports redaction — matches are replaced with `[REDACTED]`.

**Implements**: `Scanner`, `Redactor`

## PromptInjection

Detects common LLM prompt injection attempts using 15+ regex patterns.

```go
// Default patterns
s := scanners.NewPromptInjection()

// Add custom patterns
s := scanners.NewPromptInjectionWithPatterns(
    regexp.MustCompile(`(?i)custom\s+exploit`),
)
```

**Detects**:
- Override instructions ("ignore all previous instructions")
- Role hijacking ("you are now a hacker")
- Jailbreak attempts ("DAN mode", "developer mode enabled")
- System prompt manipulation ("[system]", "<< SYS >>")
- Bypass attempts ("bypass content filter")

**Implements**: `Scanner`

## Secrets

Detects API keys, tokens, and credentials.

```go
s := scanners.NewSecrets()
```

**Detects**:

| Type | Pattern |
|------|---------|
| AWS Access Key | `AKIA...` |
| GitHub Token | `ghp_...`, `gho_...` |
| OpenAI Key | `sk-...` |
| Anthropic Key | `sk-ant-...` |
| Stripe Key | `sk_live_...`, `sk_test_...` |
| Slack Token | `xoxb-...`, `xoxp-...` |
| Generic API Key | `api_key=...`, `api-secret:...` |
| Bearer Token | `Bearer ...` |
| Private Key | `-----BEGIN PRIVATE KEY-----` |
| Connection String | `postgres://...`, `mongodb://...` |

**Implements**: `Scanner`, `Redactor`

## InvisibleText

Detects hidden Unicode characters (format chars, private use) commonly used for prompt injection attacks.

```go
s := scanners.NewInvisibleText()
```

**Implements**: `Scanner`, `Redactor` (strips invisible characters)

## NoRefusal

Detects when an LLM refuses to answer using 25 known refusal phrases.

```go
s := scanners.NewNoRefusal()

// Custom phrases
s := scanners.NewNoRefusalWithPhrases("no can do", "not possible")
```

**Default phrases**: "i'm sorry", "i cannot", "as an ai", "against my guidelines", etc.

**Implements**: `Scanner`

## TokenLimit

Enforces a maximum word count on content.

```go
s := scanners.NewTokenLimit(500) // max 500 words
```

**Implements**: `Scanner`

## ReadingTime

Enforces a maximum reading time (200 words per minute).

```go
s := scanners.NewReadingTime(120) // max 2 minutes
```

**Implements**: `Scanner`

## JSONValidator

Validates JSON structure in content. Optionally checks for required keys.

```go
s := scanners.NewJSONValidator()

// With required keys
s := scanners.NewJSONValidatorWithKeys("name", "email", "age")
```

**Implements**: `Scanner`

## URLReachability

Checks that URLs in content are reachable via HTTP HEAD. Useful for detecting hallucinated URLs.

```go
s := scanners.NewURLReachability()

// Custom timeout per URL
s := scanners.NewURLReachabilityWithTimeout(3 * time.Second)
```

**Implements**: `Scanner`

## BanCode

Detects code snippets using heuristic patterns for 10+ languages.

```go
s := scanners.NewBanCode()

// With extra patterns
s := scanners.NewBanCodeWithPatterns(regexp.MustCompile(`(?m)^SELECT .+ FROM`))
```

**Detects**: Markdown code fences, Python, JavaScript/TS, Go, Java/C#, C/C++, SQL, PHP, shebang lines, framework decorators.

**Implements**: `Scanner`

## MaliciousURL

Detects potentially malicious URLs using heuristics.

```go
s := scanners.NewMaliciousURL()

// With domain blocklist
s := scanners.NewMaliciousURLWithBlocklist("evil.com", "phishing.org")
```

**Checks**: Suspicious TLDs (.tk, .ml, .xyz), IP-based hosts, excessive subdomains, phishing keywords in path.

**Implements**: `Scanner`

## Sentiment

Analyzes text sentiment using a VADER-inspired lexicon approach.

```go
s := scanners.NewSentiment() // threshold: -0.5

// Custom threshold (lower = more tolerant)
s := scanners.NewSentimentWithThreshold(-1.0)
```

**Implements**: `Scanner`

## Composing Scanners

```go
guard := guardrails.New(
    // Input safety
    guardrails.WithScanner(scanners.NewPromptInjection(), guardrails.ActionBlock),
    guardrails.WithScanner(scanners.NewToxicity(), guardrails.ActionBlock),

    // Data protection
    guardrails.WithScanner(scanners.NewPII(), guardrails.ActionRedact),
    guardrails.WithScanner(scanners.NewSecrets(), guardrails.ActionRedact),

    // Custom rules
    guardrails.WithScanner(scanners.NewBanSubstrings("competitor_name"), guardrails.ActionLog),
)
```

Scanners run in order. When a scanner with `ActionRedact` fires, subsequent scanners see the redacted content.
