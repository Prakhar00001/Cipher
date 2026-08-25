package git

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"cipher/pkg/secrets"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

type Scanner struct {
	engine *secrets.Engine
}

func NewScanner(engine *secrets.Engine) *Scanner {
	return &Scanner{engine: engine}
}

// ScanWorkingTree traverses non-ignored filesystem paths
func (s *Scanner) ScanWorkingTree(rootPath string) ([]secrets.SecretFinding, error) {
	var findings []secrets.SecretFinding

	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			name := info.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" || name == "dist" || name == "build" {
				return filepath.SkipDir
			}
			return nil
		}
		// Skip files larger than 2MB
		if info.Size() > 2*1024*1024 {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		relPath, _ := filepath.Rel(rootPath, path)
		f := s.engine.ScanContent(relPath, content)
		findings = append(findings, f...)
		return nil
	})

	return findings, err
}

// ScanHistory walks Git commit history without allocating working copy checkouts
func (s *Scanner) ScanHistory(repoPath string, maxCommits int) ([]secrets.SecretFinding, error) {
	var findings []secrets.SecretFinding

	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, err
	}

	iter, err := repo.Log(&git.LogOptions{})
	if err != nil {
		return nil, err
	}

	count := 0
	err = iter.ForEach(func(c *object.Commit) error {
		if maxCommits > 0 && count >= maxCommits {
			return io.EOF
		}
		count++

		files, err := c.Files()
		if err != nil {
			return nil
		}

		return files.ForEach(func(f *object.File) error {
			if strings.HasPrefix(f.Name, ".git/") || f.Size > 1024*1024 {
				return nil
			}

			content, err := f.Contents()
			if err != nil {
				return nil
			}

			res := s.engine.ScanContent(f.Name, []byte(content))
			for i := range res {
				res[i].CommitSHA = c.Hash.String()[:8]
				res[i].Author = c.Author.Name
				res[i].Timestamp = c.Author.When
			}
			findings = append(findings, res...)
			return nil
		})
	})

	if err == io.EOF {
		err = nil
	}
	return findings, err
}