package sca

import (
	"bufio"
	"bytes"
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	goModRequireRegex = regexp.MustCompile(`^\s*([a-zA-Z0-9.\-_/]+)\s+v([a-zA-Z0-9.\-_+]+)`)
	pyReqRegex        = regexp.MustCompile(`^([a-zA-Z0-9_\-\.]+)\s*==\s*([a-zA-Z0-9_\-\.]+)`)
)

// ParseLockfile detects the ecosystem and extracts dependencies
func ParseLockfile(path string, content []byte) ([]Package, error) {
	filename := filepath.Base(path)

	switch {
	case filename == "go.mod":
		return parseGoMod(path, content), nil
	case filename == "package-lock.json":
		return parsePackageLock(path, content)
	case filename == "requirements.txt":
		return parseRequirementsTxt(path, content), nil
	default:
		return nil, nil
	}
}

func parseGoMod(path string, content []byte) []Package {
	var pkgs []Package
	scanner := bufio.NewScanner(bytes.NewReader(content))
	inRequireBlock := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "//") || len(line) == 0 {
			continue
		}

		if line == "require (" {
			inRequireBlock = true
			continue
		}
		if inRequireBlock && line == ")" {
			inRequireBlock = false
			continue
		}

		if inRequireBlock || strings.HasPrefix(line, "require ") {
			cleanLine := strings.TrimPrefix(line, "require ")
			matches := goModRequireRegex.FindStringSubmatch(cleanLine)
			if len(matches) == 3 {
				pkgs = append(pkgs, Package{
					Name:      matches[1],
					Version:   matches[2],
					Ecosystem: EcosystemGo,
					FilePath:  path,
					Direct:    !strings.Contains(cleanLine, "// indirect"),
				})
			}
		}
	}
	return pkgs
}

type npmPackageLock struct {
	Packages     map[string]npmLockPackage `json:"packages"`
	Dependencies map[string]npmLockDep     `json:"dependencies"`
}

type npmLockPackage struct {
	Version string `json:"version"`
	Dev     bool   `json:"dev"`
}

type npmLockDep struct {
	Version  string                `json:"version"`
	Dev      bool                  `json:"dev"`
	Requires map[string]string     `json:"requires"`
}

func parsePackageLock(path string, content []byte) ([]Package, error) {
	var lock npmPackageLock
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil, err
	}

	var pkgs []Package

	// NPM v2 & v3 (packages map)
	if len(lock.Packages) > 0 {
		for pkgPath, data := range lock.Packages {
			if pkgPath == "" || data.Version == "" {
				continue
			}
			name := strings.TrimPrefix(pkgPath, "node_modules/")
			pkgs = append(pkgs, Package{
				Name:      name,
				Version:   data.Version,
				Ecosystem: EcosystemNPM,
				FilePath:  path,
				Direct:    !strings.Contains(name, "node_modules/"),
			})
		}
		return pkgs, nil
	}

	// NPM v1 (dependencies tree)
	for name, dep := range lock.Dependencies {
		pkgs = append(pkgs, Package{
			Name:      name,
			Version:   dep.Version,
			Ecosystem: EcosystemNPM,
			FilePath:  path,
			Direct:    true,
		})
	}

	return pkgs, nil
}

func parseRequirementsTxt(path string, content []byte) []Package {
	var pkgs []Package
	scanner := bufio.NewScanner(bytes.NewReader(content))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || len(line) == 0 {
			continue
		}

		matches := pyReqRegex.FindStringSubmatch(line)
		if len(matches) == 3 {
			pkgs = append(pkgs, Package{
				Name:      matches[1],
				Version:   matches[2],
				Ecosystem: EcosystemPyPI,
				FilePath:  path,
				Direct:    true,
			})
		}
	}
	return pkgs
}