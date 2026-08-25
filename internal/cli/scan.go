package cli

import (
	"os"
	"path/filepath"

	"cipher/internal/git"
	"cipher/internal/printer"
	"cipher/internal/rules"
	"cipher/pkg/sca"
	"cipher/pkg/secrets"

	"github.com/spf13/cobra"
)

var (
	scanHistory bool
	maxCommits  int
	skipSCA     bool
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan repository for secrets and vulnerable dependencies",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		targetPath := "."
		if len(args) > 0 {
			targetPath = args[0]
		}

		defaultRules := rules.GetDefaultRules()

		// Render JACKY-style orange dashboard
		printer.PrintBanner("0.1.0", targetPath, len(defaultRules))

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

		// 3. Render unified retro report
		printer.PrintReport(secretFindings, scaFindings)
		return nil
	},
}

func runSCAScan(rootPath string) []sca.DependencyFinding {
	var allPackages []sca.Package

	_ = filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			name := info.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" {
				return filepath.SkipDir
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
	RootCmd.AddCommand(scanCmd)
}