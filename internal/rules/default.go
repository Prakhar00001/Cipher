package rules

import "cipher/pkg/secrets"

// GetDefaultRules returns verified token signatures
func GetDefaultRules() []secrets.Rule {
	return []secrets.Rule{
		{
			ID:          "aws-access-key",
			Description: "AWS Access Key ID",
			Regex:       `\b(AKIA[0-9A-Z]{16})\b`,
			Keywords:    []string{"AKIA"},
			MinEntropy:  2.8,
			Severity:    secrets.SeverityCritical,
		},
		{
			ID:          "github-pat",
			Description: "GitHub Personal Access Token",
			Regex:       `\b(ghp_[a-zA-Z0-9]{36})\b`,
			Keywords:    []string{"ghp_"},
			MinEntropy:  3.5,
			Severity:    secrets.SeverityCritical,
		},
		{
			ID:          "slack-token",
			Description: "Slack Bot Token",
			Regex:       `\b(xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24})\b`,
			Keywords:    []string{"xoxb-"},
			MinEntropy:  3.0,
			Severity:    secrets.SeverityHigh,
		},
		{
			ID:          "generic-api-key",
			Description: "Generic High-Entropy API Key Assignment",
			Regex:       `(?i)(?:api_key|apikey|secret|token)\s*[:=]\s*["']?([a-zA-Z0-9_\-]{24,64})["']?`,
			Keywords:    []string{"api_key", "apikey", "secret", "token"},
			MinEntropy:  4.2,
			Severity:    secrets.SeverityMedium,
		},
	}
}