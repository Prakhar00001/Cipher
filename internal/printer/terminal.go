package printer

import (
	"fmt"
	"strings"

	"cipher/pkg/iac"
	"cipher/pkg/sca"
	"cipher/pkg/secrets"

	"github.com/charmbracelet/lipgloss"
)

const (
	ColorPrimaryOrange = "#F97316"
	ColorWarmOrange    = "#EA580C"
	ColorDeepOrange    = "#C2410C"
	ColorDarkBorder    = "#7C2D12"
	ColorMutedOrange   = "#A16207"
	ColorBrightText    = "#FED7AA"
	ColorSubtleText    = "#FDBA74"
)

var (
	bannerStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(ColorPrimaryOrange))
	taglineStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(ColorWarmOrange))
	sectionHeader = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(ColorPrimaryOrange))

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color(ColorWarmOrange)).
			Padding(0, 1).
			MarginLeft(1)

	innerBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color(ColorDarkBorder)).
			Padding(0, 1)

	divider = lipgloss.NewStyle().Foreground(lipgloss.Color(ColorDarkBorder))

	labelStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color(ColorMutedOrange))
	valueStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color(ColorSubtleText))
	brightStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(ColorBrightText))
	highlightStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(ColorPrimaryOrange))

	critStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF3B30"))
	highStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(ColorPrimaryOrange))
	medStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(ColorWarmOrange))
	okStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(ColorPrimaryOrange))
	robotStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(ColorPrimaryOrange))
)

const asciiHeader = `
 ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗ 
██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗
██║     ██║██████╔╝███████║█████╗  ██████╔╝
██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗
╚██████╗██║██║     ██║  ██║███████╗██║  ██║
 ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝`

const asciiRobot = `
   ╭───────╮   
   │ ◉   ◉ │   
   │   ▽   │   
   ╰───┬───╯   
      _│_      
   [ CIPHER ]  `

func PrintBanner(version string, targetPath string, rulesCount int) {
	fmt.Println(bannerStyle.Render(asciiHeader))
	fmt.Println(taglineStyle.Render(" >_ AI & STATIC SECURITY ENGINE • TERMINAL-NATIVE ANALYZER"))
	fmt.Println()

	leftCol := fmt.Sprintf("%s\n\n%s\n%s %s\n%s %s",
		robotStyle.Render(asciiRobot),
		labelStyle.Render("session:"),
		labelStyle.Render("target: "), valueStyle.Render(targetPath),
		labelStyle.Render("status: "), okStyle.Render("ARMED [OK]"),
	)

	rightCol := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n\n%s\n%s\n%s",
		highlightStyle.Render("Active Subsystems"),
		fmt.Sprintf("  %s %s", labelStyle.Render("secrets:"), valueStyle.Render(fmt.Sprintf("%d signatures (entropy + regex)", rulesCount))),
		fmt.Sprintf("  %s %s", labelStyle.Render("history:"), valueStyle.Render("zero-alloc packfile stream")),
		fmt.Sprintf("  %s %s", labelStyle.Render("sca:    "), valueStyle.Render("osv.dev vulnerability graph")),
		fmt.Sprintf("  %s %s", labelStyle.Render("iac:    "), valueStyle.Render("dockerfile & k8s static linter")),
		highlightStyle.Render("Intelligence & Heuristics"),
		fmt.Sprintf("  %s %s", labelStyle.Render("entropy:"), valueStyle.Render("shannon class variance (H >= 3.0)")),
		fmt.Sprintf("  %s %s", labelStyle.Render("context:"), valueStyle.Render("mock/fixture auto-deprioritization")),
	)

	grid := lipgloss.JoinHorizontal(lipgloss.Top,
		innerBoxStyle.Render(leftCol),
		"  ",
		rightCol,
	)

	headerBox := fmt.Sprintf("%s %s\n\n%s",
		highlightStyle.Render("CIPHER --INIT"),
		labelStyle.Render("v"+version),
		grid,
	)

	fmt.Println(boxStyle.Render(headerBox))
	fmt.Println()
}

func PrintReport(secretFindings []secrets.SecretFinding, scaFindings []sca.DependencyFinding, iacFindings []iac.MisconfigFinding) {
	total := len(secretFindings) + len(scaFindings) + len(iacFindings)

	statusLine := fmt.Sprintf("─── [ SCAN RESULTS: %d FINDINGS ] ──────────────────────────────────────────", total)
	fmt.Println(divider.Render(statusLine))
	fmt.Println()

	// Section 1: Secrets
	fmt.Printf("%s\n", sectionHeader.Render("● CREDENTIAL & SECRET LEAKS"))
	if len(secretFindings) == 0 {
		fmt.Println("  " + okStyle.Render("✔ No credentials detected."))
	} else {
		for _, f := range secretFindings {
			sev := medStyle.Render("MED ")
			if f.Severity == secrets.SeverityCritical {
				sev = critStyle.Render("CRIT")
			} else if f.Severity == secrets.SeverityHigh {
				sev = highStyle.Render("HIGH")
			}

			loc := fmt.Sprintf("%s:%d:%d", f.Path, f.LineNumber, f.ColumnStart)
			if f.CommitSHA != "" {
				loc = fmt.Sprintf("[%s] %s (%s)", f.CommitSHA, loc, f.Author)
			}

			fmt.Printf("  [%s] %s %s\n", sev, highlightStyle.Render(f.Description), labelStyle.Render("("+f.RuleID+")"))
			fmt.Printf("         %s %s\n", labelStyle.Render("loc:    "), valueStyle.Render(loc))
			fmt.Printf("         %s %s\n", labelStyle.Render("token:  "), critStyle.Render(f.MatchSnippet))
			fmt.Printf("         %s %s\n", labelStyle.Render("metrics:"), valueStyle.Render(fmt.Sprintf("entropy: %.2f | confidence: %.0f%%", f.Entropy, f.Confidence*100)))
			fmt.Println(divider.Render("  ──────────────────────────────────────────────────────────────────────"))
		}
	}

	fmt.Println()

	// Section 2: SCA
	fmt.Printf("%s\n", sectionHeader.Render("● DEPENDENCY VULNERABILITIES (SCA)"))
	if len(scaFindings) == 0 {
		fmt.Println("  " + okStyle.Render("✔ No known CVEs detected in lockfiles."))
	} else {
		for _, df := range scaFindings {
			depType := "direct"
			if !df.Package.Direct {
				depType = "transitive"
			}

			fmt.Printf("  📦 %s @ %s %s\n",
				highlightStyle.Render(df.Package.Name),
				brightStyle.Render(df.Package.Version),
				labelStyle.Render(fmt.Sprintf("(%s, %s)", df.Package.Ecosystem, depType)),
			)
			fmt.Printf("     %s %s\n", labelStyle.Render("manifest:"), valueStyle.Render(df.Package.FilePath))

			for _, v := range df.Vulnerabilities {
				summary := v.Summary
				if summary == "" && len(v.Details) > 0 {
					summary = strings.Split(v.Details, "\n")[0]
				}
				if len(summary) > 75 {
					summary = summary[:72] + "..."
				}

				aliasStr := ""
				if len(v.Aliases) > 0 {
					aliasStr = fmt.Sprintf(" [%s]", strings.Join(v.Aliases, ", "))
				}

				fmt.Printf("     • %s %s%s\n",
					critStyle.Render(v.ID),
					valueStyle.Render(summary),
					labelStyle.Render(aliasStr),
				)
			}
			fmt.Println(divider.Render("  ──────────────────────────────────────────────────────────────────────"))
		}
	}

	fmt.Println()

	// Section 3: IaC Misconfigurations
	fmt.Printf("%s\n", sectionHeader.Render("● IAC & CONFIGURATION MISCONFIGURATIONS"))
	if len(iacFindings) == 0 {
		fmt.Println("  " + okStyle.Render("✔ No IaC misconfigurations detected."))
	} else {
		for _, f := range iacFindings {
			sev := medStyle.Render("MED ")
			if f.Severity == iac.SeverityCritical {
				sev = critStyle.Render("CRIT")
			} else if f.Severity == iac.SeverityHigh {
				sev = highStyle.Render("HIGH")
			}

			loc := fmt.Sprintf("%s:%d", f.Path, f.LineNumber)
			fmt.Printf("  [%s] %s %s\n", sev, highlightStyle.Render(f.Description), labelStyle.Render("("+f.RuleID+")"))
			fmt.Printf("         %s %s (%s)\n", labelStyle.Render("target: "), valueStyle.Render(loc), f.TargetType)
			if f.Snippet != "" {
				fmt.Printf("         %s %s\n", labelStyle.Render("code:   "), critStyle.Render(f.Snippet))
			}
			fmt.Printf("         %s %s\n", labelStyle.Render("action: "), valueStyle.Render(f.Remediation))
			fmt.Println(divider.Render("  ──────────────────────────────────────────────────────────────────────"))
		}
	}

	fmt.Println()
	fmt.Println(taglineStyle.Render("> cipher ready. run 'cipher --help' for commands."))
}