package iac

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
)

var (
	fromLatestRegex = regexp.MustCompile(`(?i)^FROM\s+[\w\.\-/]+:latest\b`)
	fromNoTagRegex  = regexp.MustCompile(`(?i)^FROM\s+([a-zA-Z0-9_\-\./]+)\s*$`)
	sudoRegex       = regexp.MustCompile(`(?i)\bsudo\b`)
)

func scanDockerfile(path string, content []byte) []MisconfigFinding {
	var findings []MisconfigFinding
	scanner := bufio.NewScanner(bytes.NewReader(content))
	lineNum := 0
	hasUserDirective := false

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || len(line) == 0 {
			continue
		}

		// 1. Missing explicit tag / Using :latest
		if strings.HasPrefix(strings.ToUpper(line), "FROM ") {
			if fromLatestRegex.MatchString(line) || fromNoTagRegex.MatchString(line) {
				findings = append(findings, MisconfigFinding{
					RuleID:      "DOCKER-001",
					TargetType:  TargetDockerfile,
					Description: "Base image uses mutable ':latest' or unpinned tag",
					Path:        path,
					LineNumber:  lineNum,
					Severity:    SeverityMedium,
					Remediation: "Pin base image to a specific immutable digest or SemVer tag (e.g. alpine:3.19.1)",
					Snippet:     line,
				})
			}
		}

		// 2. Insecure ADD instruction
		if strings.HasPrefix(strings.ToUpper(line), "ADD ") && !strings.Contains(line, ".tar.") {
			findings = append(findings, MisconfigFinding{
				RuleID:      "DOCKER-002",
				TargetType:  TargetDockerfile,
				Description: "Insecure use of ADD instruction instead of COPY",
				Path:        path,
				LineNumber:  lineNum,
				Severity:    SeverityLow,
				Remediation: "Use COPY instead of ADD unless auto-extracting tarballs",
				Snippet:     line,
			})
		}

		// 3. Sudo usage in container
		if strings.HasPrefix(strings.ToUpper(line), "RUN ") && sudoRegex.MatchString(line) {
			findings = append(findings, MisconfigFinding{
				RuleID:      "DOCKER-003",
				TargetType:  TargetDockerfile,
				Description: "Usage of 'sudo' inside container build layer",
				Path:        path,
				LineNumber:  lineNum,
				Severity:    SeverityHigh,
				Remediation: "Avoid sudo; configure non-root users using the USER instruction",
				Snippet:     line,
			})
		}

		if strings.HasPrefix(strings.ToUpper(line), "USER ") {
			hasUserDirective = true
		}
	}

	// 4. Missing USER instruction (runs as root by default)
	if !hasUserDirective && lineNum > 0 {
		findings = append(findings, MisconfigFinding{
			RuleID:      "DOCKER-004",
			TargetType:  TargetDockerfile,
			Description: "Container executes as root (missing USER instruction)",
			Path:        path,
			LineNumber:  1,
			Severity:    SeverityHigh,
			Remediation: "Specify a non-root execution user via 'USER <uid>:<gid>' before runtime ENTRYPOINT/CMD",
		})
	}

	return findings
}