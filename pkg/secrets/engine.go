package secrets

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"

	"cipher/pkg/entropy"
)

type CompiledRule struct {
	Rule
	CompiledRegex *regexp.Regexp
}

type Engine struct {
	rules []CompiledRule
}

func NewEngine(rules []Rule) (*Engine, error) {
	var compiled []CompiledRule
	for _, r := range rules {
		re, err := regexp.Compile(r.Regex)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, CompiledRule{
			Rule:          r,
			CompiledRegex: re,
		})
	}
	return &Engine{rules: compiled}, nil
}

// ScanContent executes the 3-stage detection pipeline:
// Stage 0: Fast keyword rejection
// Stage 1: Regular expression match extraction
// Stage 2: Shannon entropy filter & contextual confidence penalty
func (e *Engine) ScanContent(path string, content []byte) []SecretFinding {
	var findings []SecretFinding
	isTestFile := isTestPath(path)

	scanner := bufio.NewScanner(bytes.NewReader(content))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()

		for _, rule := range e.rules {
			// Stage 0: Substring keyword pre-check
			if len(rule.Keywords) > 0 {
				matched := false
				lowerLine := bytes.ToLower(line)
				for _, kw := range rule.Keywords {
					if bytes.Contains(lowerLine, []byte(strings.ToLower(kw))) {
						matched = true
						break
					}
				}
				if !matched {
					continue
				}
			}

			// Stage 1: Regex scan
			matches := rule.CompiledRegex.FindAllIndex(line, -1)
			for _, matchIndices := range matches {
				start, end := matchIndices[0], matchIndices[1]
				extracted := string(line[start:end])

				// Stage 2: Entropy gate
				ent := entropy.Shannon(extracted)
				if rule.MinEntropy > 0 && ent < rule.MinEntropy {
					continue
				}

				// Stage 3: Context confidence rating
				confidence := calculateConfidence(path, line, isTestFile)
				if confidence < 0.30 {
					continue
				}

				findings = append(findings, SecretFinding{
					RuleID:       rule.ID,
					Description:  rule.Description,
					Path:         path,
					LineNumber:   lineNum,
					ColumnStart:  start + 1,
					ColumnEnd:    end + 1,
					MatchSnippet: maskSecret(extracted),
					Entropy:      ent,
					Severity:     rule.Severity,
					Confidence:   confidence,
					IsTestOrMock: isTestFile,
				})
			}
		}
	}
	return findings
}

func isTestPath(path string) bool {
	p := strings.ToLower(path)
	return strings.Contains(p, "test") ||
		strings.Contains(p, "fixture") ||
		strings.Contains(p, "mock") ||
		strings.Contains(p, "_spec.") ||
		strings.HasSuffix(p, "_test.go")
}

func calculateConfidence(path string, line []byte, isTest bool) float64 {
	conf := 0.90
	lineStr := strings.ToLower(string(line))

	if isTest {
		conf -= 0.35
	}
	if strings.Contains(lineStr, "mock") || strings.Contains(lineStr, "example") || strings.Contains(lineStr, "fake") {
		conf -= 0.30
	}
	if strings.Contains(lineStr, "your-api-key") || strings.Contains(lineStr, "xxxx") || strings.Contains(lineStr, "123456") {
		conf -= 0.50
	}
	if conf < 0 {
		return 0
	}
	return conf
}

func maskSecret(s string) string {
	if len(s) <= 6 {
		return "******"
	}
	return s[:3] + strings.Repeat("*", len(s)-6) + s[len(s)-3:]
}