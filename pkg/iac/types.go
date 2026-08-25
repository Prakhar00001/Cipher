package iac

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

type TargetType string

const (
	TargetDockerfile TargetType = "Dockerfile"
	TargetKubernetes TargetType = "Kubernetes"
	TargetGitHubCI   TargetType = "GitHubActions"
)

type MisconfigFinding struct {
	RuleID      string     `json:"rule_id"`
	TargetType  TargetType `json:"target_type"`
	Description string     `json:"description"`
	Path        string     `json:"path"`
	LineNumber  int        `json:"line_number"`
	Severity    Severity   `json:"severity"`
	Remediation string     `json:"remediation"`
	Snippet     string     `json:"snippet,omitempty"`
}