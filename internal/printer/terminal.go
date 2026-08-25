package printer

import (
	"fmt"

	"cipher/pkg/secrets"

	"github.com/charmbracelet/lipgloss"
)

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#005F87")).
			Padding(0, 1)

	critStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF0055"))
	highStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF8800"))
	medStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFCC00"))
	infoStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#666666"))
)

func PrintFindings(findings []secrets.SecretFinding) {
	fmt.Println()
	fmt.Println(titleStyle.Render(fmt.Sprintf(" CIPHER SECURITY SCAN: %d FINDINGS ", len(findings))))
	fmt.Println()

	if len(findings) == 0 {
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#04B575")).Render("✔ Clean! No secrets or credentials detected."))
		return
	}

	for _, f := range findings {
		var sev string
		switch f.Severity {
		case secrets.SeverityCritical:
			sev = critStyle.Render(string(f.Severity))
		case secrets.SeverityHigh:
			sev = highStyle.Render(string(f.Severity))
		default:
			sev = medStyle.Render(string(f.Severity))
		}

		location := fmt.Sprintf("%s:%d:%d", f.Path, f.LineNumber, f.ColumnStart)
		if f.CommitSHA != "" {
			location = fmt.Sprintf("[%s] %s (by %s)", f.CommitSHA, location, f.Author)
		}

		fmt.Printf("[%s] %s (%s)\n", sev, f.Description, f.RuleID)
		fmt.Printf("  File:       %s\n", location)
		fmt.Printf("  Snippet:    %s\n", f.MatchSnippet)
		fmt.Printf("  Entropy:    %.2f  Confidence: %.0f%%\n", f.Entropy, f.Confidence*100)
		fmt.Println(infoStyle.Render("  ──────────────────────────────────────────────"))
	}
}