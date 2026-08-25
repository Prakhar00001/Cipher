package perms

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type Auditor struct{}

func NewAuditor() *Auditor {
	return &Auditor{}
}

// AuditFile inspects permissions, naming semantics, and metadata risks
func (a *Auditor) AuditFile(path string, info os.FileInfo) []PermissionFinding {
	var findings []PermissionFinding
	mode := info.Mode()
	perm := mode.Perm()
	octal := fmt.Sprintf("%04o", perm)
	filename := strings.ToLower(filepath.Base(path))

	// POSIX-specific checks (Disabled on Windows where permissions default to 0666)
	if runtime.GOOS != "windows" {
		// 1. World-Writable Files (0666 / 0777 or other-write bit enabled)
		if perm&0002 != 0 {
			findings = append(findings, PermissionFinding{
				RuleID:      "PERM-001",
				Path:        path,
				FileMode:    mode.String(),
				OctalMode:   octal,
				Severity:    SeverityHigh,
				Description: "File is world-writable (allows arbitrary local tampering)",
				Remediation: fmt.Sprintf("Restrict permissions: run 'chmod o-w %s' or 'chmod 644 %s'", path, path),
			})
		}

		// 2. Overly Permissive Private Keys
		if isPrivateKey(filename) {
			if perm > 0600 {
				findings = append(findings, PermissionFinding{
					RuleID:      "PERM-002",
					Path:        path,
					FileMode:    mode.String(),
					OctalMode:   octal,
					Severity:    SeverityCritical,
					Description: "Private cryptographic key file has loose permissions (accessible by group/others)",
					Remediation: fmt.Sprintf("Secure key permissions: run 'chmod 600 %s'", path),
				})
			}
		}

		// 3. Sensitive Environment Files
		if isEnvFile(filename) {
			if perm > 0600 {
				findings = append(findings, PermissionFinding{
					RuleID:      "PERM-003",
					Path:        path,
					FileMode:    mode.String(),
					OctalMode:   octal,
					Severity:    SeverityMedium,
					Description: "Environment credential file is readable beyond the owning user",
					Remediation: fmt.Sprintf("Secure environment file: run 'chmod 600 %s'", path),
				})
			}
		}

		// 5. SUID / SGID executable flags
		if mode&os.ModeSetuid != 0 || mode&os.ModeSetgid != 0 {
			findings = append(findings, PermissionFinding{
				RuleID:      "PERM-005",
				Path:        path,
				FileMode:    mode.String(),
				OctalMode:   octal,
				Severity:    SeverityHigh,
				Description: "File has SUID/SGID bit enabled (potential local privilege escalation vector)",
				Remediation: fmt.Sprintf("Remove special bits: run 'chmod u-s,g-s %s'", path),
			})
		}
	}

	// 4. Exposed Database and SQL Backup Artifacts (Applies to all Operating Systems)
	if isDatabaseOrDump(filename) {
		findings = append(findings, PermissionFinding{
			RuleID:      "PERM-004",
			Path:        path,
			FileMode:    mode.String(),
			OctalMode:   octal,
			Severity:    SeverityHigh,
			Description: "Database file or SQL dump tracked in repository tree",
			Remediation: fmt.Sprintf("Remove from Git tracking, add '%s' to .gitignore, and purge from history", filename),
		})
	}

	return findings
}

func isPrivateKey(name string) bool {
	return strings.HasPrefix(name, "id_rsa") ||
		strings.HasPrefix(name, "id_ed25519") ||
		strings.HasPrefix(name, "id_ecdsa") ||
		strings.HasSuffix(name, ".pem") ||
		strings.HasSuffix(name, ".key") ||
		strings.HasSuffix(name, ".pkcs8")
}

func isEnvFile(name string) bool {
	return name == ".env" ||
		(strings.HasPrefix(name, ".env.") && !strings.HasSuffix(name, ".example"))
}

func isDatabaseOrDump(name string) bool {
	return strings.HasSuffix(name, ".sqlite") ||
		strings.HasSuffix(name, ".sqlite3") ||
		strings.HasSuffix(name, ".sql.dump") ||
		(strings.HasSuffix(name, ".sql") && !strings.Contains(name, "migration") && !strings.Contains(name, "schema"))
}