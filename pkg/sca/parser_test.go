package sca

import (
	"testing"
)

func TestParseGoMod(t *testing.T) {
	content := []byte(`module cipher

go 1.22

require (
	github.com/charmbracelet/lipgloss v0.10.0
	github.com/spf13/cobra v1.8.0 // indirect
)
`)

	pkgs, err := ParseLockfile("go.mod", content)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(pkgs) != 2 {
		t.Fatalf("Expected 2 packages, got %d", len(pkgs))
	}

	if pkgs[0].Name != "github.com/charmbracelet/lipgloss" || !pkgs[0].Direct {
		t.Errorf("Direct package parsed incorrectly: %+v", pkgs[0])
	}

	if pkgs[1].Name != "github.com/spf13/cobra" || pkgs[1].Direct {
		t.Errorf("Indirect package parsed incorrectly: %+v", pkgs[1])
	}
}

func TestParseRequirementsTxt(t *testing.T) {
	content := []byte(`
# Core dependencies
requests==2.28.1
flask==2.0.1
`)

	pkgs, err := ParseLockfile("requirements.txt", content)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(pkgs) != 2 {
		t.Fatalf("Expected 2 packages, got %d", len(pkgs))
	}

	if pkgs[0].Name != "requests" || pkgs[0].Version != "2.28.1" {
		t.Errorf("Requests package mismatch: %+v", pkgs[0])
	}
}