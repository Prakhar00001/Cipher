package sca

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const osvBatchURL = "https://api.osv.dev/v1/querybatch"

type OSVBatchRequest struct {
	Queries []OSVQuery `json:"queries"`
}

type OSVQuery struct {
	Package OSVPackage `json:"package"`
	Version string     `json:"version"`
}

type OSVPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type OSVBatchResponse struct {
	Results []OSVResult `json:"results"`
}

type OSVResult struct {
	Vulns []OSVVuln `json:"vulns"`
}

type OSVVuln struct {
	ID        string    `json:"id"`
	Summary   string    `json:"summary"`
	Details   string    `json:"details"`
	Aliases   []string  `json:"aliases"`
	Published time.Time `json:"published"`
}

type Client struct {
	httpClient *http.Client
}

func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// QueryBatch queries the OSV database for a list of resolved packages
func (c *Client) QueryBatch(packages []Package) ([]DependencyFinding, error) {
	if len(packages) == 0 {
		return nil, nil
	}

	var queries []OSVQuery
	for _, p := range packages {
		queries = append(queries, OSVQuery{
			Package: OSVPackage{
				Name:      p.Name,
				Ecosystem: string(p.Ecosystem),
			},
			Version: p.Version,
		})
	}

	reqBody, err := json.Marshal(OSVBatchRequest{Queries: queries})
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Post(osvBatchURL, "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("OSV API connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned HTTP status %d", resp.StatusCode)
	}

	var batchResp OSVBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
		return nil, err
	}

	var findings []DependencyFinding
	for i, res := range batchResp.Results {
		if len(res.Vulns) > 0 {
			var vulns []Vulnerability
			for _, v := range res.Vulns {
				vulns = append(vulns, Vulnerability{
					ID:        v.ID,
					Aliases:   v.Aliases,
					Summary:   v.Summary,
					Details:   v.Details,
					Published: v.Published,
				})
			}
			findings = append(findings, DependencyFinding{
				Package:         packages[i],
				Vulnerabilities: vulns,
			})
		}
	}

	return findings, nil
}