package iac

import (
	"bufio"
	"bytes"
	"strings"
)

func scanKubernetesYAML(path string, content []byte) []MisconfigFinding {
	var findings []MisconfigFinding
	scanner := bufio.NewScanner(bytes.NewReader(content))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || len(line) == 0 {
			continue
		}

		// 1. Privileged container flag
		if strings.Contains(line, "privileged: true") {
			findings = append(findings, MisconfigFinding{
				RuleID:      "K8S-001",
				TargetType:  TargetKubernetes,
				Description: "Container requested privileged execution mode",
				Path:        path,
				LineNumber:  lineNum,
				Severity:    SeverityCritical,
				Remediation: "Set 'securityContext.privileged: false' and grant granular Linux capabilities instead",
				Snippet:     line,
			})
		}

		// 2. hostNetwork enabled
		if strings.Contains(line, "hostNetwork: true") {
			findings = append(findings, MisconfigFinding{
				RuleID:      "K8S-002",
				TargetType:  TargetKubernetes,
				Description: "Pod shares host network namespace (hostNetwork: true)",
				Path:        path,
				LineNumber:  lineNum,
				Severity:    SeverityHigh,
				Remediation: "Disable hostNetwork to prevent pod sniffing node-level network interfaces",
				Snippet:     line,
			})
		}

		// 3. hostPID enabled
		if strings.Contains(line, "hostPID: true") {
			findings = append(findings, MisconfigFinding{
				RuleID:      "K8S-003",
				TargetType:  TargetKubernetes,
				Description: "Pod shares host PID namespace (hostPID: true)",
				Path:        path,
				LineNumber:  lineNum,
				Severity:    SeverityHigh,
				Remediation: "Disable hostPID to isolate container processes from the underlying host",
				Snippet:     line,
			})
		}
	}

	return findings
}