package secrets

import "time"

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

type SecretFinding struct {
	RuleID       string    `json:"rule_id"`
	Description  string    `json:"description"`
	Path         string    `json:"path"`
	LineNumber   int       `json:"line_number"`
	ColumnStart  int       `json:"column_start"`
	ColumnEnd    int       `json:"column_end"`
	MatchSnippet string    `json:"match_snippet"`
	Entropy      float64   `json:"entropy"`
	Severity     Severity  `json:"severity"`
	Confidence   float64   `json:"confidence"` // 0.0 to 1.0 based on context heuristics
	IsTestOrMock bool      `json:"is_test_or_mock"`
	CommitSHA    string    `json:"commit_sha,omitempty"`
	Author       string    `json:"author,omitempty"`
	Timestamp    time.Time `json:"timestamp,omitempty"`
}

type Rule struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Regex       string   `json:"regex"`
	Keywords    []string `json:"keywords"`
	MinEntropy  float64  `json:"min_entropy"`
	Severity    Severity `json:"severity"`
}