package iac

import (
	"testing"
)

func TestScanDockerfile(t *testing.T) {
	dockerfile := []byte(`
FROM alpine:latest
RUN sudo apt-get update
ADD app.py /app/app.py
`)

	engine := NewEngine()
	findings := engine.ScanContent("Dockerfile", dockerfile)

	if len(findings) < 3 {
		t.Fatalf("Expected at least 3 findings, got %d", len(findings))
	}
}

func TestScanKubernetesYAML(t *testing.T) {
	k8sYAML := []byte(`
apiVersion: v1
kind: Pod
metadata:
  name: insecure-pod
spec:
  hostNetwork: true
  containers:
  - name: web
    image: nginx
    securityContext:
      privileged: true
`)

	engine := NewEngine()
	findings := engine.ScanContent("deploy/pod.yaml", k8sYAML)

	if len(findings) != 2 {
		t.Fatalf("Expected 2 Kubernetes findings, got %d", len(findings))
	}
}