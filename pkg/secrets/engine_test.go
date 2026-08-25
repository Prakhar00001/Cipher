package secrets

import (
	"testing"
)

func TestEngine_ScanContent(t *testing.T) {
	rules := []Rule{
		{
			ID:          "aws-key",
			Description: "AWS Key",
			Regex:       `\b(AKIA[0-9A-Z]{16})\b`,
			Keywords:    []string{"AKIA"},
			MinEntropy:  2.8,
			Severity:    SeverityCritical,
		},
	}

	engine, err := NewEngine(rules)
	if err != nil {
		t.Fatalf("Failed to instantiate engine: %v", err)
	}

	content := []byte("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
	findings := engine.ScanContent("config/prod.env", content)

	if len(findings) != 1 {
		t.Fatalf("Expected 1 finding, got %d", len(findings))
	}

	if findings[0].RuleID != "aws-key" {
		t.Errorf("Expected rule ID 'aws-key', got %q", findings[0].RuleID)
	}

	expectedMask := "AKI**************PLE"
	if findings[0].MatchSnippet != expectedMask {
		t.Errorf("Expected snippet %q, got %q", expectedMask, findings[0].MatchSnippet)
	}
}