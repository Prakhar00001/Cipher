package config

import (
	"os"
	"path/filepath"
	"strings"

	"cipher/pkg/iac"
	"cipher/pkg/perms"
	"cipher/pkg/sca"
	"cipher/pkg/secrets"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Version     string         `yaml:"version"`
	FailOn      string         `yaml:"fail_on"`
	Ignore      IgnoreConfig   `yaml:"ignore"`
	CustomRules []CustomRule   `yaml:"custom_rules"`
}

type IgnoreConfig struct {
	Paths        []string `yaml:"paths"`
	Rules        []string `yaml:"rules"`
	Fingerprints []string `yaml:"fingerprints"`
}

type CustomRule struct {
	ID          string   `yaml:"id"`
	Description string   `yaml:"description"`
	Regex       string   `yaml:"regex"`
	Keywords    []string `yaml:"keywords"`
	MinEntropy  float64  `yaml:"min_entropy"`
	Severity    string   `yaml:"severity"`
}

// LoadConfig attempts to load .cipher.yml or .cipher.yaml from target path or root
func LoadConfig(dir string) (*Config, error) {
	candidates := []string{
		filepath.Join(dir, ".cipher.yml"),
		filepath.Join(dir, ".cipher.yaml"),
		".cipher.yml",
		".cipher.yaml",
	}

	for _, path := range candidates {
		if data, err := os.ReadFile(path); err == nil {
			var cfg Config
			if err := yaml.Unmarshal(data, &cfg); err != nil {
				return nil, err
			}
			return &cfg, nil
		}
	}

	// Default configuration if no file exists
	return &Config{
		Version: "1",
		FailOn:  "",
	}, nil
}

// ConvertCustomRules converts user-defined custom rules into internal Secret Rules
func (c *Config) ConvertCustomRules() []secrets.Rule {
	var rules []secrets.Rule
	for _, cr := range c.CustomRules {
		sev := secrets.SeverityMedium
		switch strings.ToUpper(cr.Severity) {
		case "CRITICAL":
			sev = secrets.SeverityCritical
		case "HIGH":
			sev = secrets.SeverityHigh
		case "LOW":
			sev = secrets.SeverityLow
		}

		rules = append(rules, secrets.Rule{
			ID:          cr.ID,
			Description: cr.Description,
			Regex:       cr.Regex,
			Keywords:    cr.Keywords,
			MinEntropy:  cr.MinEntropy,
			Severity:    sev,
		})
	}
	return rules
}

// FilterSecrets removes findings matching ignored paths, rule IDs, or token fingerprints
func (c *Config) FilterSecrets(findings []secrets.SecretFinding) []secrets.SecretFinding {
	var filtered []secrets.SecretFinding
	for _, f := range findings {
		if c.isPathIgnored(f.Path) || c.isRuleIgnored(f.RuleID) || c.isFingerprintIgnored(f.MatchSnippet) {
			continue
		}
		filtered = append(filtered, f)
	}
	return filtered
}

// FilterSCA removes SCA vulnerabilities matching ignored manifests or rule/CVE IDs
func (c *Config) FilterSCA(findings []sca.DependencyFinding) []sca.DependencyFinding {
	var filtered []sca.DependencyFinding
	for _, df := range findings {
		if c.isPathIgnored(df.Package.FilePath) {
			continue
		}

		var activeVulns []sca.Vulnerability
		for _, v := range df.Vulnerabilities {
			if !c.isRuleIgnored(v.ID) {
				activeVulns = append(activeVulns, v)
			}
		}

		if len(activeVulns) > 0 {
			df.Vulnerabilities = activeVulns
			filtered = append(filtered, df)
		}
	}
	return filtered
}

// FilterIaC removes IaC findings matching ignored paths or rule IDs
func (c *Config) FilterIaC(findings []iac.MisconfigFinding) []iac.MisconfigFinding {
	var filtered []iac.MisconfigFinding
	for _, f := range findings {
		if c.isPathIgnored(f.Path) || c.isRuleIgnored(f.RuleID) {
			continue
		}
		filtered = append(filtered, f)
	}
	return filtered
}

// FilterPerms removes permission findings matching ignored paths or rule IDs
func (c *Config) FilterPerms(findings []perms.PermissionFinding) []perms.PermissionFinding {
	var filtered []perms.PermissionFinding
	for _, f := range findings {
		if c.isPathIgnored(f.Path) || c.isRuleIgnored(f.RuleID) {
			continue
		}
		filtered = append(filtered, f)
	}
	return filtered
}

func (c *Config) isPathIgnored(path string) bool {
	normalized := filepath.ToSlash(path)
	for _, pattern := range c.Ignore.Paths {
		match, _ := filepath.Match(pattern, normalized)
		if match || strings.Contains(normalized, strings.Trim(pattern, "*")) {
			return true
		}
	}
	return false
}

func (c *Config) isRuleIgnored(ruleID string) bool {
	for _, r := range c.Ignore.Rules {
		if strings.EqualFold(r, ruleID) {
			return true
		}
	}
	return false
}

func (c *Config) isFingerprintIgnored(snippet string) bool {
	for _, fp := range c.Ignore.Fingerprints {
		if strings.Contains(snippet, fp) {
			return true
		}
	}
	return false
}