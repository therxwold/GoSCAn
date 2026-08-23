package epss

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/therxwold/GoSCAn/internal/model"
)

// Client queries the FIRST EPSS API for CVE exploitation probabilities.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

// apiResponse models the score rows returned by the FIRST EPSS API.
type apiResponse struct {
	Data []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
		Date       string `json:"date"`
	} `json:"data"`
}

// Query returns EPSS scores keyed by CVE identifier.
func (c Client) Query(ctx context.Context, cves []string) (map[string]model.EPSS, error) {
	out := map[string]model.EPSS{}
	if len(cves) == 0 {
		return out, nil
	}
	base := c.BaseURL
	if base == "" {
		base = "https://api.first.org/data/v1/epss"
	}
	hc := c.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}

	for _, batch := range chunkCVEs(cves, 1800) {
		u, err := url.Parse(base)
		if err != nil {
			return nil, err
		}
		q := u.Query()
		q.Set("cve", strings.Join(batch, ","))
		u.RawQuery = q.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		resp, err := hc.Do(req)
		if err != nil {
			return nil, fmt.Errorf("EPSS query: %w", err)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			resp.Body.Close()
			return nil, fmt.Errorf("EPSS query: HTTP %d", resp.StatusCode)
		}
		var data apiResponse
		err = json.NewDecoder(resp.Body).Decode(&data)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("decode EPSS response: %w", err)
		}
		for _, row := range data.Data {
			score, e1 := strconv.ParseFloat(row.EPSS, 64)
			pct, e2 := strconv.ParseFloat(row.Percentile, 64)
			if e1 != nil || e2 != nil {
				continue
			}
			out[row.CVE] = model.EPSS{Score: score, Percentile: pct, Date: row.Date}
		}
	}
	return out, nil
}

// chunkCVEs deduplicates identifiers and groups them under a query-length limit.
func chunkCVEs(cves []string, maxChars int) [][]string {
	var batches [][]string
	var cur []string
	chars := 0
	seen := map[string]bool{}
	for _, cve := range cves {
		if cve == "" || seen[cve] {
			continue
		}
		seen[cve] = true
		need := len(cve)
		if len(cur) > 0 {
			need++
		}
		if len(cur) > 0 && chars+need > maxChars {
			batches = append(batches, cur)
			cur = nil
			chars = 0
		}
		cur = append(cur, cve)
		chars += len(cve)
		if len(cur) > 1 {
			chars++
		}
	}
	if len(cur) > 0 {
		batches = append(batches, cur)
	}
	return batches
}
