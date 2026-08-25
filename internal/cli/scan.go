package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cipher/internal/git"
	"cipher/internal/printer"
	"cipher/internal/rules"
	"cipher/pkg/config"
	"cipher/pkg/iac"
	"cipher/pkg/perms"
	"cipher/pkg/sarif"
	"cipher/pkg/sca"
	"cipher/pkg/secrets"

	"github.com/spf13/cobra"
)

var (
	scanHistory  bool
	maxCommits   int
	skipSCA      bool
	skipIaC      bool
	skipPerms    bool
	outputFormat string
	outputFile   string
	failOn       string
)

type FullReportJSON struct {
	Secrets     []secrets.SecretFinding   `json:"secrets"`
	SCA         []sca.DependencyFinding   `json:"sca"`
	IaC         []iac.MisconfigFinding    `json:"iac"`
	Permissions []perms.PermissionFinding `json:"permissions"`
}

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan repository for secrets, vulnerabilities, misconfigurations, and permissions",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		targetPath := "."
		if len(args) > 0 {
			targetPath = args[0]
		}

		// Load .cipher.yml configuration
		cfg, err := config.LoadConfig(targetPath)
		if err != nil {
			return fmt.Errorf("failed to parse .cipher.yml: %w", err)
		}

		// Merge default + custom rules
		allRules := append(rules.GetDefaultRules(), cfg.ConvertCustomRules()...)

		// 1. Secrets Engine
		engine, err := secrets.NewEngine(allRules)
		if err != nil {
			return err
		}

		scanner := git.NewScanner(engine)
		var secretFindings []secrets.SecretFinding

		if scanHistory {
			secretFindings, err = scanner.ScanHistory(targetPath, maxCommits)
		} else {
			secretFindings, err = scanner.ScanWorkingTree(targetPath)
		}
		if err != nil {
			return err
		}
		secretFindings = cfg.FilterSecrets(secretFindings)

		// 2. SCA Engine
		var scaFindings []sca.DependencyFinding
		if !skipSCA {
			scaFindings = cfg.FilterSCA(runSCAScan(targetPath))
		}

		// 3. IaC Engine
		var iacFindings []iac.MisconfigFinding
		if !skipIaC {
			iacFindings = cfg.FilterIaC(runIaCScan(targetPath))
		}

		// 4. Permissions Engine
		var permFindings []perms.PermissionFinding
		if !skipPerms {
			permFindings = cfg.FilterPerms(runPermsScan(targetPath))
		}

		// 5. Output Formatting
		switch outputFormat {
		case "sarif":
			data, err := sarif.GenerateSARIF("0.4.0", secretFindings, scaFindings, iacFindings, permFindings)
			if err != nil {
				return err
			}
			if err := writeOutput(data); err != nil {
				return err
			}
		case "json":
			full := FullReportJSON{
				Secrets:     secretFindings,
				SCA:         scaFindings,
				IaC:         iacFindings,
				Permissions: permFindings,
			}
			data, err := json.MarshalIndent(full, "", "  ")
			if err != nil {
				return err
			}
			if err := writeOutput(data); err != nil {
				return err
			}
		default:
			printer.PrintBanner("0.4.0", targetPath, len(allRules))
			printer.PrintReport(secretFindings, scaFindings, iacFindings, permFindings)
		}

		// 6. Evaluate Fail-On Gatekeeping
		threshold := failOn
		if threshold == "" {
			threshold = cfg.FailOn
		}

		if threshold != "" && shouldFailBuild(threshold, secretFindings, scaFindings, iacFindings, permFindings) {
			return fmt.Errorf("security scan failed: vulnerabilities exceed policy threshold (%s)", strings.ToUpper(threshold))
		}

		return nil
	},
}

func shouldFailBuild(
	threshold string,
	secretsList []secrets.SecretFinding,
	scaList []sca.DependencyFinding,
	iacList []iac.MisconfigFinding,
	permsList []perms.PermissionFinding,
) bool {
	targetWeight := severityWeight(threshold)

	for _, f := range secretsList {
		if severityWeight(string(f.Severity)) >= targetWeight {
			return true
		}
	}
	for _, df := range scaList {
		if len(df.Vulnerabilities) > 0 && severityWeight("CRITICAL") >= targetWeight {
			return true
		}
	}
	for _, f := range iacList {
		if severityWeight(string(f.Severity)) >= targetWeight {
			return true
		}
	}
	for _, f := range permsList {
		if severityWeight(string(f.Severity)) >= targetWeight {
			return true
		}
	}
	return false
}

func severityWeight(sev string) int {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func writeOutput(data []byte) error {
	if outputFile != "" {
		return os.WriteFile(outputFile, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

func runPermsScan(rootPath string) []perms.PermissionFinding {
	var findings []perms.PermissionFinding
	auditor := perms.NewAuditor()

	_ = filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			name := info.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}

		relPath, _ := filepath.Rel(rootPath, path)
		f := auditor.AuditFile(relPath, info)
		findings = append(findings, f...)
		return nil
	})

	return findings
}

func runIaCScan(rootPath string) []iac.MisconfigFinding {
	var findings []iac.MisconfigFinding
	engine := iac.NewEngine()

	_ = filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			if info != nil && info.IsDir() {
				name := info.Name()
				if name == ".git" || name == "node_modules" || name == "vendor" {
					return filepath.SkipDir
				}
			}
			return nil
		}

		content, readErr := os.ReadFile(path)
		if readErr == nil {
			relPath, _ := filepath.Rel(rootPath, path)
			f := engine.ScanContent(relPath, content)
			findings = append(findings, f...)
		}
		return nil
	})

	return findings
}

func runSCAScan(rootPath string) []sca.DependencyFinding {
	var allPackages []sca.Package

	_ = filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			if info != nil && info.IsDir() {
				name := info.Name()
				if name == ".git" || name == "node_modules" || name == "vendor" {
					return filepath.SkipDir
				}
			}
			return nil
		}

		filename := info.Name()
		if filename == "go.mod" || filename == "package-lock.json" || filename == "requirements.txt" {
			content, readErr := os.ReadFile(path)
			if readErr == nil {
				relPath, _ := filepath.Rel(rootPath, path)
				pkgs, parseErr := sca.ParseLockfile(relPath, content)
				if parseErr == nil && len(pkgs) > 0 {
					allPackages = append(allPackages, pkgs...)
				}
			}
		}
		return nil
	})

	if len(allPackages) == 0 {
		return nil
	}

	client := sca.NewClient()
	findings, err := client.QueryBatch(allPackages)
	if err != nil {
		return nil
	}
	return findings
}

func init() {
	scanCmd.Flags().BoolVarP(&scanHistory, "history", "H", false, "Scan full git commit history for secrets")
	scanCmd.Flags().IntVarP(&maxCommits, "max-commits", "m", 50, "Max commits to analyze in history mode")
	scanCmd.Flags().BoolVar(&skipSCA, "skip-sca", false, "Skip dependency vulnerability analysis")
	scanCmd.Flags().BoolVar(&skipIaC, "skip-iac", false, "Skip IaC misconfiguration analysis")
	scanCmd.Flags().BoolVar(&skipPerms, "skip-perms", false, "Skip filesystem permission audit")
	scanCmd.Flags().StringVarP(&outputFormat, "format", "f", "terminal", "Output format: terminal, json, sarif")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write output directly to file path")
	scanCmd.Flags().StringVar(&failOn, "fail-on", "", "Exit with error code if findings meet threshold: critical, high, medium, low")
	RootCmd.AddCommand(scanCmd)
}