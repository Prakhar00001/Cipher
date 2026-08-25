package sarif

import (
	"encoding/json"

	"cipher/pkg/iac"
	"cipher/pkg/sca"
	"cipher/pkg/secrets"
)

// GenerateSARIF generates a valid SARIF v2.1.0 document from scan findings
func GenerateSARIF(
	version string,
	secretFindings []secrets.SecretFinding,
	scaFindings []sca.DependencyFinding,
	iacFindings []iac.MisconfigFinding,
) ([]byte, error) {
	rulesMap := make(map[string]Rule)
	var results []Result

	// 1. Process Secrets
	for _, f := range secretFindings {
		level := mapSeverity(string(f.Severity))
		if _, exists := rulesMap[f.RuleID]; !exists {
			rulesMap[f.RuleID] = Rule{
				ID:               f.RuleID,
				ShortDescription: MultiformatMessage{Text: f.Description},
				DefaultConfiguration: &RuleConfiguration{
					Level: level,
				},
			}
		}

		results = append(results, Result{
			RuleID:  f.RuleID,
			Level:   level,
			Message: MultiformatMessage{Text: f.Description + " detected: " + f.MatchSnippet},
			Locations: []Location{
				{
					PhysicalLocation: PhysicalLocation{
						ArtifactLocation: ArtifactLocation{URI: f.Path},
						Region: Region{
							StartLine:   f.LineNumber,
							StartColumn: f.ColumnStart,
							EndColumn:   f.ColumnEnd,
						},
					},
				},
			},
		})
	}

	// 2. Process SCA Findings
	for _, df := range scaFindings {
		for _, v := range df.Vulnerabilities {
			ruleID := v.ID
			if _, exists := rulesMap[ruleID]; !exists {
				rulesMap[ruleID] = Rule{
					ID:               ruleID,
					ShortDescription: MultiformatMessage{Text: v.Summary},
					DefaultConfiguration: &RuleConfiguration{
						Level: "error",
					},
				}
			}

			results = append(results, Result{
				RuleID:  ruleID,
				Level:   "error",
				Message: MultiformatMessage{Text: df.Package.Name + "@" + df.Package.Version + " is vulnerable to " + v.ID + ": " + v.Summary},
				Locations: []Location{
					{
						PhysicalLocation: PhysicalLocation{
							ArtifactLocation: ArtifactLocation{URI: df.Package.FilePath},
							Region: Region{
								StartLine: 1,
							},
						},
					},
				},
			})
		}
	}

	// 3. Process IaC Findings
	for _, f := range iacFindings {
		level := mapSeverity(string(f.Severity))
		if _, exists := rulesMap[f.RuleID]; !exists {
			rulesMap[f.RuleID] = Rule{
				ID:               f.RuleID,
				ShortDescription: MultiformatMessage{Text: f.Description},
				DefaultConfiguration: &RuleConfiguration{
					Level: level,
				},
			}
		}

		results = append(results, Result{
			RuleID:  f.RuleID,
			Level:   level,
			Message: MultiformatMessage{Text: f.Description + " - Remediation: " + f.Remediation},
			Locations: []Location{
				{
					PhysicalLocation: PhysicalLocation{
						ArtifactLocation: ArtifactLocation{URI: f.Path},
						Region: Region{
							StartLine: f.LineNumber,
						},
					},
				},
			},
		})
	}

	var rules []Rule
	for _, r := range rulesMap {
		rules = append(rules, r)
	}

	report := Report{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []Run{
			{
				Tool: Tool{
					Driver: Driver{
						Name:           "Cipher",
						Version:        version,
						InformationURI: "https://github.com/Prakhar00001/Cipher",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	return json.MarshalIndent(report, "", "  ")
}

func mapSeverity(sev string) string {
	switch sev {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	default:
		return "note"
	}
}