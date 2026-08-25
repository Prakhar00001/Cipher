package cli

import "github.com/spf13/cobra"

var RootCmd = &cobra.Command{
	Use:   "cipher",
	Short: "Cipher — High-Performance Repository Security Scanner",
	Long:  "Fast, precise, terminal-native security analyzer for repositories and Git history.",
}

func Execute() error {
	return RootCmd.Execute()
}