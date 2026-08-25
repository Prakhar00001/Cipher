package perms

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAuditor_AuditFile(t *testing.T) {
	tmpDir := t.TempDir()
	auditor := NewAuditor()

	// 1. POSIX permission test (Unix only)
	if runtime.GOOS != "windows" {
		keyPath := filepath.Join(tmpDir, "id_rsa")
		if err := os.WriteFile(keyPath, []byte("fake-key"), 0644); err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		info, err := os.Stat(keyPath)
		if err != nil {
			t.Fatalf("Stat failed: %v", err)
		}

		findings := auditor.AuditFile(keyPath, info)
		if len(findings) == 0 {
			t.Errorf("Expected PERM-002 finding on key with mode 0644, got none")
		}
	}

	// 2. Database/dump artifact test (Cross-platform)
	dumpPath := filepath.Join(tmpDir, "backup.sql.dump")
	if err := os.WriteFile(dumpPath, []byte("DUMP"), 0600); err != nil {
		t.Fatalf("Failed to write test dump: %v", err)
	}

	dumpInfo, _ := os.Stat(dumpPath)
	dumpFindings := auditor.AuditFile(dumpPath, dumpInfo)

	foundDumpRule := false
	for _, f := range dumpFindings {
		if f.RuleID == "PERM-004" {
			foundDumpRule = true
			break
		}
	}

	if !foundDumpRule {
		t.Errorf("Expected PERM-004 on SQL dump file, got: %+v", dumpFindings)
	}
}