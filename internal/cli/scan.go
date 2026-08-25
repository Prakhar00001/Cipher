package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"cipher/internal/git"
	"cipher/internal/printer"
	"cipher/internal/rules"
	"cipher/pkg/iac"
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
	outputFormat string
	outputFile   string
)

type FullReportJSON struct {
	Secrets   []secrets.SecretFinding `json:"secrets"`
	SCA       []sca.DependencyFinding `json:"sca"`
	IaC       []iac.MisconfigFinding  `json:"iac"`
}

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan repository for secrets, vulnerabilities, and misconfigurations",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		targetPath := "."
		if len(args) > 0 {
			targetPath = args[0]
		}

		defaultRules := rules.GetDefaultRules()

		// 1. Secrets Engine
		engine, err := secrets.NewEngine(defaultRules)
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

		// 2. SCA Engine
		var scaFindings []sca.DependencyFinding
		if !skipSCA {
			scaFindings = runSCAScan(targetPath)
		}

		// 3. IaC Engine
		var iacFindings []iac.MisconfigFinding
		if !skipIaC {
			iacFindings = runIaCScan(targetPath)
		}

		// 4. Output Routing
		switch outputFormat {
		case "sarif":
			data, err := sarif.GenerateSARIF("0.2.0", secretFindings, scaFindings, iacFindings)
			if err != nil {
				return err
			}
			return writeOutput(data)
		case "json":
			full := FullReportJSON{
				Secrets: secretFindings,
				SCA:     scaFindings,
				IaC:     iacFindings,
			}
			data, err := json.MarshalIndent(full, "", "  ")
			if err != nil {
				return err
			}
			return writeOutput(data)
		default:
			printer.PrintBanner("0.2.0", targetPath, len(defaultRules))
			printer.PrintReport(secretFindings, scaFindings, iacFindings)
			return nil
		}
	},
}

func writeOutput(data []byte) error {
	if outputFile != "" {
		return os.WriteFile(outputFile, data, 0644)
	}
	fmt.Println(string(data))
	return nil
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
	scanCmd.Flags().StringVarP(&outputFormat, "format", "f", "terminal", "Output format: terminal, json, sarif")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write output directly to file path")
	RootCmd.AddCommand(scanCmd)
}