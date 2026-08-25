package sca

import "time"

type Ecosystem string

const (
	EcosystemGo     Ecosystem = "Go"
	EcosystemNPM    Ecosystem = "npm"
	EcosystemPyPI   Ecosystem = "PyPI"
	EcosystemMaven  Ecosystem = "Maven"
)

type Package struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Ecosystem Ecosystem `json:"ecosystem"`
	FilePath  string    `json:"file_path"`
	Direct    bool      `json:"direct"`
}

type Vulnerability struct {
	ID          string    `json:"id"`
	Aliases     []string  `json:"aliases"`
	Summary     string    `json:"summary"`
	Details     string    `json:"details"`
	Severity    string    `json:"severity"`
	FixedIn     string    `json:"fixed_in,omitempty"`
	Published   time.Time `json:"published"`
	References  []string  `json:"references,omitempty"`
}

type DependencyFinding struct {
	Package         Package         `json:"package"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}