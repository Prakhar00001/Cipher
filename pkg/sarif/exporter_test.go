package sarif

import (
	"encoding/json"
	"testing"

	"cipher/pkg/secrets"
)

func TestGenerateSARIF(t *testing.T) {
	findings := []secrets.SecretFinding{
		{
			RuleID:       "aws-test-key",
			Description:  "AWS Secret Key",
			Path:         "main.go",
			LineNumber:   10,
			ColumnStart:  1,
			ColumnEnd:    20,
			MatchSnippet: "AKIA************",
			Severity:     secrets.SeverityCritical,
		},
	}

	sarifBytes, err := GenerateSARIF("0.2.0", findings, nil, nil)
	if err != nil {
		t.Fatalf("Failed to generate SARIF: %v", err)
	}

	var report Report
	if err := json.Unmarshal(sarifBytes, &report); err != nil {
		t.Fatalf("Generated invalid JSON: %v", err)
	}

	if report.Version != "2.1.0" {
		t.Errorf("Expected SARIF version 2.1.0, got %s", report.Version)
	}

	if len(report.Runs[0].Results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(report.Runs[0].Results))
	}
}