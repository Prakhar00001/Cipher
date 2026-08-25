package iac

import (
	"path/filepath"
	"strings"
)

type Engine struct{}

func NewEngine() *Engine {
	return &Engine{}
}

// ScanContent routes files to appropriate IaC analyzers based on filename patterns
func (e *Engine) ScanContent(path string, content []byte) []MisconfigFinding {
	filename := filepath.Base(path)
	lowerPath := strings.ToLower(path)

	// Dockerfile scanner
	if strings.EqualFold(filename, "Dockerfile") || strings.HasPrefix(filename, "Dockerfile.") || strings.HasSuffix(filename, ".dockerfile") {
		return scanDockerfile(path, content)
	}

	// Kubernetes YAML scanner
	if strings.HasSuffix(lowerPath, ".yaml") || strings.HasSuffix(lowerPath, ".yml") {
		if isK8sManifest(content) {
			return scanKubernetesYAML(path, content)
		}
	}

	return nil
}

func isK8sManifest(content []byte) bool {
	str := string(content)
	return strings.Contains(str, "apiVersion:") && strings.Contains(str, "kind:")
}