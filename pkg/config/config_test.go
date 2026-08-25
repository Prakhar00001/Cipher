package config

import (
	"testing"

	"cipher/pkg/secrets"
)

func TestFilterSecrets(t *testing.T) {
	cfg := &Config{
		Ignore: IgnoreConfig{
			Paths:        []string{"testdata/*", "fixtures/**"},
			Rules:        []string{"aws-key"},
			Fingerprints: []string{"SAMPLE_TOKEN"},
		},
	}

	findings := []secrets.SecretFinding{
		{RuleID: "aws-key", Path: "main.go", MatchSnippet: "AKIAIOSFODNN7EXAMPLE"},
		{RuleID: "stripe-key", Path: "testdata/mock.go", MatchSnippet: "sk_live_123456"},
		{RuleID: "stripe-key", Path: "prod.go", MatchSnippet: "SAMPLE_TOKEN_123"},
		{RuleID: "stripe-key", Path: "prod.go", MatchSnippet: "sk_live_validtoken"},
	}

	filtered := cfg.FilterSecrets(findings)

	if len(filtered) != 1 {
		t.Fatalf("Expected exactly 1 surviving finding, got %d", len(filtered))
	}

	if filtered[0].MatchSnippet != "sk_live_validtoken" {
		t.Errorf("Unexpected retained finding: %+v", filtered[0])
	}
}