package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/therxwold/GoSCAn/internal/model"
)

// Client queries the NVD CVE API 2.0 for CVE metadata.
type Client struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
}

// Record contains NVD metadata used to enrich a GoSCAn finding.
type Record struct {
	ID             string
	Description    string
	Severity       model.Severity
	CVSS           *model.CVSS
	CWEs           []string
	References     []string
	KnownExploited bool
}

type apiResponse struct {
	Vulnerabilities []struct {
		CVE apiCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type apiCVE struct {
	ID           string `json:"id"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		V40 []metric `json:"cvssMetricV40"`
		V31 []metric `json:"cvssMetricV31"`
		V30 []metric `json:"cvssMetricV30"`
		V2  []metric `json:"cvssMetricV2"`
	} `json:"metrics"`
	Weaknesses []struct {
		Description []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"description"`
	} `json:"weaknesses"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
	CISAExploitAdd string `json:"cisaExploitAdd"`
}

type metric struct {
	Type     string `json:"type"`
	CVSSData struct {
		Version      string  `json:"version"`
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"`
}

// Query returns NVD records keyed by CVE identifier.
func (c Client) Query(ctx context.Context, cves []string) (map[string]Record, error) {
	out := map[string]Record{}
	cves = unique(cves)
	if len(cves) == 0 {
		return out, nil
	}
	base := c.BaseURL
	if base == "" {
		base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	}
	hc := c.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}

	for i := 0; i < len(cves); i += 100 {
		end := i + 100
		if end > len(cves) {
			end = len(cves)
		}
		u, err := url.Parse(base)
		if err != nil {
			return nil, err
		}
		q := u.Query()
		q.Set("cveIds", strings.Join(cves[i:end], ","))
		u.RawQuery = q.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "goscan")
		if c.APIKey != "" {
			req.Header.Set("apiKey", c.APIKey)
		}
		resp, err := hc.Do(req)
		if err != nil {
			return nil, fmt.Errorf("NVD query: %w", err)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			return nil, fmt.Errorf("NVD query: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		var data apiResponse
		err = json.NewDecoder(resp.Body).Decode(&data)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("decode NVD response: %w", err)
		}
		for _, item := range data.Vulnerabilities {
			r := normalize(item.CVE)
			if r.ID != "" {
				out[r.ID] = r
			}
		}
	}
	return out, nil
}

func normalize(cve apiCVE) Record {
	r := Record{ID: cve.ID, KnownExploited: cve.CISAExploitAdd != ""}
	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			r.Description = d.Value
			break
		}
	}
	if r.Description == "" && len(cve.Descriptions) > 0 {
		r.Description = cve.Descriptions[0].Value
	}
	for _, weakness := range cve.Weaknesses {
		for _, d := range weakness.Description {
			if strings.HasPrefix(d.Value, "CWE-") {
				r.CWEs = append(r.CWEs, d.Value)
			}
		}
	}
	for _, ref := range cve.References {
		if ref.URL != "" {
			r.References = append(r.References, ref.URL)
		}
	}
	r.CWEs = unique(r.CWEs)
	r.References = unique(r.References)
	for _, group := range [][]metric{cve.Metrics.V40, cve.Metrics.V31, cve.Metrics.V30, cve.Metrics.V2} {
		for _, m := range group {
			if m.CVSSData.BaseScore <= 0 {
				continue
			}
			candidate := &model.CVSS{
				Version: m.CVSSData.Version,
				Vector:  m.CVSSData.VectorString,
				Score:   m.CVSSData.BaseScore,
				Source:  string(model.SourceNVD),
			}
			if r.CVSS == nil || candidate.Score > r.CVSS.Score {
				r.CVSS = candidate
				severity := m.CVSSData.BaseSeverity
				if severity == "" {
					severity = m.BaseSeverity
				}
				r.Severity = parseSeverity(severity)
			}
		}
	}
	return r
}

func parseSeverity(v string) model.Severity {
	switch strings.ToLower(v) {
	case "critical":
		return model.SeverityCritical
	case "high":
		return model.SeverityHigh
	case "medium", "moderate":
		return model.SeverityMedium
	case "low":
		return model.SeverityLow
	default:
		return model.SeverityUnknown
	}
}

func unique(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
