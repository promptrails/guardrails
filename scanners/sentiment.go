package scanners

import (
	"context"
	"fmt"
	"math"
	"strings"

	"github.com/promptrails/guardrails"
)

// Simplified VADER-inspired sentiment lexicon.
// Positive values = positive sentiment, negative = negative.
var sentimentLexicon = map[string]float64{
	// Strongly negative
	"terrible": -3.0, "horrible": -3.0, "awful": -3.0, "worst": -3.0,
	"disgusting": -3.0, "pathetic": -2.5, "dreadful": -2.5, "atrocious": -3.0,
	// Moderately negative
	"bad": -2.0, "poor": -2.0, "disappointing": -2.0, "annoying": -2.0,
	"frustrating": -2.0, "unpleasant": -2.0, "ugly": -2.0, "boring": -1.5,
	"mediocre": -1.0, "difficult": -1.0, "sad": -2.0, "angry": -2.0,
	"fail": -2.0, "failed": -2.0, "broken": -2.0, "useless": -2.5,
	"slow": -1.0, "expensive": -1.0, "confusing": -1.5, "complicated": -1.0,
	"wrong": -2.0, "error": -1.5, "problem": -1.5, "issue": -1.0,
	// Mildly negative
	"not": -1.0, "don't": -1.0, "doesn't": -1.0, "isn't": -1.0,
	"can't": -1.0, "won't": -1.0, "never": -1.5, "nothing": -1.0,
	// Strongly positive
	"excellent": 3.0, "amazing": 3.0, "wonderful": 3.0, "fantastic": 3.0,
	"outstanding": 3.0, "brilliant": 3.0, "perfect": 3.0, "superb": 3.0,
	// Moderately positive
	"good": 2.0, "great": 2.5, "nice": 1.5, "awesome": 2.5,
	"love": 2.5, "beautiful": 2.5, "helpful": 2.0, "easy": 1.5,
	"fast": 1.5, "best": 2.5, "happy": 2.0, "enjoy": 2.0,
	"recommend": 2.0, "impressive": 2.5, "reliable": 2.0, "smooth": 1.5,
	"clean": 1.5, "simple": 1.5, "fun": 2.0, "useful": 2.0,
	// Mildly positive
	"ok": 0.5, "okay": 0.5, "fine": 0.5, "decent": 1.0,
	"like": 1.0, "thank": 1.5, "thanks": 1.5, "please": 0.5,
	// Intensifiers
	"very": 0, "really": 0, "extremely": 0, "absolutely": 0,
	"totally": 0, "completely": 0, "quite": 0,
}

// Intensifier multiplier.
var intensifiers = map[string]float64{
	"very": 1.5, "really": 1.5, "extremely": 2.0, "absolutely": 2.0,
	"totally": 1.5, "completely": 1.5, "quite": 1.2, "so": 1.3,
}

// Sentiment analyzes text sentiment using a VADER-inspired lexicon approach.
// Returns negative result if sentiment score falls below the threshold.
type Sentiment struct {
	threshold float64 // score below this = negative (default: -0.5)
}

// NewSentiment creates a sentiment scanner that blocks negative content.
// Default threshold: -0.5 (moderately negative).
func NewSentiment() *Sentiment {
	return &Sentiment{threshold: -0.5}
}

// NewSentimentWithThreshold creates a scanner with a custom threshold.
// Lower values = more tolerant. Range: -3 to 3.
func NewSentimentWithThreshold(threshold float64) *Sentiment {
	return &Sentiment{threshold: threshold}
}

func (s *Sentiment) Type() guardrails.ScannerType { return "sentiment" }

func (s *Sentiment) Scan(_ context.Context, content string) *guardrails.Result {
	score := s.analyze(content)

	if score >= s.threshold {
		return &guardrails.Result{Passed: true, Scanner: s.Type()}
	}

	return &guardrails.Result{
		Passed:  false,
		Scanner: s.Type(),
		Message: fmt.Sprintf("negative sentiment detected (score: %.2f, threshold: %.2f)", score, s.threshold),
	}
}

func (s *Sentiment) analyze(content string) float64 {
	words := strings.Fields(strings.ToLower(content))
	if len(words) == 0 {
		return 0
	}

	var total float64
	var count int
	prevIntensifier := 1.0

	for _, word := range words {
		// Clean punctuation
		clean := strings.Trim(word, ".,!?;:\"'()[]")

		if mult, ok := intensifiers[clean]; ok {
			prevIntensifier = mult
			continue
		}

		if val, ok := sentimentLexicon[clean]; ok && val != 0 {
			total += val * prevIntensifier
			count++
		}
		prevIntensifier = 1.0
	}

	if count == 0 {
		return 0
	}

	// Normalize by sqrt of word count (VADER-inspired)
	normalized := total / math.Sqrt(float64(count)+1)

	// Clamp to [-3, 3]
	if normalized > 3 {
		normalized = 3
	}
	if normalized < -3 {
		normalized = -3
	}

	return normalized
}
