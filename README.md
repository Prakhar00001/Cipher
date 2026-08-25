<div align="center">

# <span style="color:#EA580C;">⚡ CIPHER</span>

<a href="https://github.com/Prakhar00001/Cipher">
  <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=800&size=40&letterSpacing=8px&duration=1&pause=1000&color=EA580C&center=true&vCenter=true&width=500&height=70&lines=CIPHER" alt="CIPHER" />
</a>

<p align="center">
  <code>&gt;_ AI &amp; STATIC SECURITY ENGINE • TERMINAL-NATIVE ANALYZER</code>
</p>

### **Terminal-Native Static Security Analyzer & DevSecOps Gatekeeper**

[![CI & Security Scan](https://github.com/Prakhar00001/Cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/Prakhar00001/Cipher/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Prakhar00001/Cipher?color=orange&label=release)](https://github.com/Prakhar00001/Cipher/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-orange.svg)](https://opensource.org/licenses/MIT)

<p align="center">
  <b>Cipher</b> is a unified, high-performance static security analysis CLI built in Go.<br/>
  It inspects codebases, Git packfiles, dependencies, and container manifests in milliseconds to detect hardcoded secrets, open-source CVEs, IaC misconfigurations, and filesystem permission vulnerabilities before they reach production.
</p>

</div>


---

## ⚡ Key Highlights

* **🏎️ Zero-Allocation Packfile Crawler**: Inspects full Git commit histories and branch trees directly via low-level object streaming without checking out intermediate commits to disk.
* **🛡️ 3-Stage Secrets Detection Pipeline**: Combines Boyer-Moore keyword fast paths, compiled regex matching, Shannon character-class entropy analysis ($H \ge 3.0$), and context heuristics to eliminate false positives.
* **📦 Live Software Composition Analysis (SCA)**: Real-time, batched dependency vulnerability lookups via the OSV.dev graph API supporting Go (`go.mod`), Node.js (`package-lock.json` v1–v3), and Python (`requirements.txt`).
* **🐳 Infrastructure-as-Code (IaC) Auditing**: Scans `Dockerfile` and Kubernetes Pod manifests for root user execution, unpinned `:latest` tags, unsafe `ADD` instructions, and privileged host namespaces.
* **🔐 Filesystem & Permission Auditor**: Evaluates POSIX permission bits to catch world-writable configs, unencrypted private keys (`id_rsa`, `.pem`), and lingering SQLite/SQL database dumps.
* **📊 OASIS SARIF v2.1.0 Standardized Exporter**: Native JSON and SARIF output formats for native integration into GitHub Code Scanning Alerts, GitLab SAST, and DefectDojo.
* **🎨 Retro Terminal UI**: Jacky/Claude-inspired terracotta orange monochrome interface powered by Lipgloss.

---


🏗️ Architecture & Pipeline Flow

                              Target Repository / Working Tree
                                             │
                    ┌────────────────────────┼────────────────────────┐
                    ▼                        ▼                        ▼
           ┌────────────────┐       ┌────────────────┐       ┌────────────────┐
           │  Git History   │       │ Lockfile Parse │       │  IaC / Config  │
           │  Packfile AST  │       │ (Go, npm, Py)  │       │ Docker/K8s AST │
           └───────┬────────┘       └───────┬────────┘       └───────┬────────┘
                   │                        │                        │
                   ▼                        ▼                        ▼
           ┌────────────────┐       ┌────────────────┐       ┌────────────────┐
           │ Secrets Engine │       │  OSV.dev Batch │       │ Static Linter  │
           │ Regex+Entropy  │       │   API Client   │       │ Policy Rules   │
           └───────┬────────┘       └───────┬────────┘       └───────┬────────┘
                   │                        │                        │
                   └────────────────────────┼────────────────────────┘
                                             │
                                             ▼
                                 ┌──────────────────────┐
                                 │ Policy & Allowlist   │
                                 │ Filter (.cipher.yml) │
                                 └──────────┬───────────┘
                                            │
                            ┌───────────────┴───────────────┐
                            ▼                               ▼
                 ┌─────────────────────┐         ┌─────────────────────┐
                 │ Lipgloss Terminal UI│         │  SARIF v2.1 / JSON  │
                 │  Interactive Cards  │         │   CI/CD Artifact    │
                 └─────────────────────┘         └─────────────────────┘




📂 Project Structure

```text
Cipher/
├── .github/
│   └── workflows/
│       ├── ci.yml                 
│       └── release.yml            
├── cmd/
│   └── cipher/
│       └── main.go                
├── internal/
│   ├── cli/
│   │   ├── root.go                
│   │   └── scan.go                
│   ├── git/
│   │   └── walker.go              
│   ├── printer/
│   │   └── terminal.go            
│   └── rules/
│       └── default.go           
├── pkg/
│   ├── config/
│   │   ├── config.go              
│   │   └── config_test.go        
│   ├── entropy/
│   │   ├── shannon.go             
│   │   └── shannon_test.go        
│   ├── iac/
│   │   ├── docker.go              
│   │   ├── engine.go              
│   │   ├── engine_test.go        
│   │   ├── k8s.go                 
│   │   └── types.go               
│   ├── perms/
│   │   ├── auditor.go             
│   │   ├── auditor_test.go       
│   │   └── types.go              
│   ├── sarif/
│   │   ├── exporter_test.go       
│   │   └── types.go              
│   ├── sca/
│   │   ├── client.go              
│   │   ├── parser.go              
│   │   ├── parser_test.go         
│   │   └── types.go               
│   └── secrets/
│       ├── engine.go             
│       ├── engine_test.go        
│       └── types.go               
├── .cipher.yml                   
├── .gitignore                     
├── go.mod                         
├── go.sum                         
├── Makefile                       
└── README.md                      


🚀 Installation

Option 1: Install via Go(Recommended for Developers)

go install [github.com/Prakhar00001/Cipher/cmd/cipher@latest]
(https://github.com/Prakhar00001/Cipher/cmd/cipher@latest)

Option 2: Build from Source

# Clone the repository
git clone [https://github.com/Prakhar00001/Cipher.git](https://github.com/Prakhar00001/Cipher.git)
cd Cipher

# Compile binary
go build -o cipher ./cmd/cipher

# Verify installation
./cipher --help

💻 CLI Usage & Commands

1. Basic Working Tree Scan

Inspects all source files, manifests, and configs in the target directory:
cipher scan .

2. Deep Git History Scan

Crawls Git commit history to find credentials committed in past revisions:
# Scan default history (last 50 commits)
cipher scan --history .

# Scan specific commit depth
cipher scan --history --max-commits 200 .

3. CI/CD Output (SARIF & JSON)

Generate machine-readable reports for continuous integration pipelines:
# Export standard SARIF v2.1.0 for GitHub Code Scanning
cipher scan --format sarif --output cipher-report.sarif .

# Export structured JSON for custom dashboards
cipher scan --format json --output report.json .

4. Build Gatekeeping (--fail-on)

Enforce pass/fail security policies in CI/CD builds:
# Fail with exit code 1 if findings meet or exceed HIGH severity
cipher scan --fail-on=high .

# Fail only on CRITICAL findings
cipher scan --fail-on=critical .

5. Selective Analyzer Execution

Skip specific subsystems when running targeted checks:
# Run secrets audit only (skipping SCA, IaC, and Permissions)
cipher scan --skip-sca --skip-iac --skip-perms .


⚙️ Configuration Reference (.cipher.yml)


Add a .cipher.yml file to the root of your repository to define allowlists, custom regex rules, and severity thresholds:

version: "1"

# Severity threshold to fail CI builds: "critical" | "high" | "medium" | "low"
fail_on: "high"

# Ignore false positives, mock files, and acceptable risks
ignore:
  paths:
    - "testdata/**"
    - "fixtures/**"
    - "vendor/**"
    - "**/*_test.go"
  rules:
    - "PERM-001"          # Ignore world-writable warnings
    - "DOCKER-001"        # Allow unpinned tags on local dev containers
  fingerprints:
    - "AKIAIOSFODNN7EXAMPLE" # Mock key in unit tests

# Define custom proprietary signatures without modifying source code
custom_rules:
  - id: "internal-api-key"
    description: "Company Internal Production Token"
    regex: 'org_sec_[a-zA-Z0-9]{32}'
    keywords: ["org_sec_"]
    min_entropy: 3.5
    severity: "CRITICAL"


🔄 GitHub Actions CI/CD Integration


Embed Cipher directly into your GitHub repository to generate automated Code Scanning security alerts:

name: Security Audit

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

permissions:
  contents: read
  security-events: write

jobs:
  cipher-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - name: Build Cipher
        run: go build -o cipher ./cmd/cipher

      - name: Run Cipher Scan
        run: ./cipher scan --format sarif --output results.sarif --fail-on=high .

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
          category: cipher-static-analysis


🧪 Testing

Run the test suite across all sub-packages:

# Run all unit tests
go test -v ./...

# Run tests with race condition detector (Linux / macOS)
go test -v -race ./...


