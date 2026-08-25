package cli

import (
	"cipher/internal/git"
	"cipher/internal/printer"
	"cipher/internal/rules"
	"cipher/pkg/secrets"

	"github.com/spf13/cobra"
)

var (
	scanHistory bool
	maxCommits  int
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan repository or directory for security risks",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		targetPath := "."
		if len(args) > 0 {
			targetPath = args[0]
		}

		engine, err := secrets.NewEngine(rules.GetDefaultRules())
		if err != nil {
			return err
		}

		scanner := git.NewScanner(engine)
		var findings []secrets.SecretFinding

		if scanHistory {
			findings, err = scanner.ScanHistory(targetPath, maxCommits)
		} else {
			findings, err = scanner.ScanWorkingTree(targetPath)
		}

		if err != nil {
			return err
		}

		printer.PrintFindings(findings)
		return nil
	},
}

func init() {
	scanCmd.Flags().BoolVarP(&scanHistory, "history", "H", false, "Scan full git commit history")
	scanCmd.Flags().IntVarP(&maxCommits, "max-commits", "m", 50, "Max commits to analyze in history mode")
	RootCmd.AddCommand(scanCmd)
}