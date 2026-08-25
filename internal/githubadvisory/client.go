package githubadvisory

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/therxwold/GoSCAn/internal/goversion"
	"github.com/therxwold/GoSCAn/internal/httpclient"
	"github.com/therxwold/GoSCAn/internal/httpjson"
	"github.com/therxwold/GoSCAn/internal/model"
	"golang.org/x/sync/errgroup"
)

// maxConcurrentAdvisoryRequests bounds GitHub API pressure and worker allocation.
const maxConcurrentAdvisoryRequests = 6

// Client queries the GitHub Advisory Database for reviewed public advisories.
type Client struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

// Record contains GitHub advisory metadata used to enrich a GoSCAn finding.
type Record struct {
	GHSAID           string
	CVEID            string
	Summary          string
	Description      string
	Severity         model.Severity
	CVSS             *model.CVSS
	CWEs             []string
	References       []string
	FirstPatchedByGo map[string]string
}

// apiAdvisory models the GitHub REST representation used during normalization.
type apiAdvisory struct {
	GHSAID         string   `json:"ghsa_id"`
	CVEID          string   `json:"cve_id"`
	Summary        string   `json:"summary"`
	Description    string   `json:"description"`
	Type           string   `json:"type"`
	Severity       string   `json:"severity"`
	References     []string `json:"references"`
	CVSSSeverities struct {
		V3 struct {
			Vector string  `json:"vector_string"`
			Score  float64 `json:"score"`
		} `json:"cvss_v3"`
		V4 struct {
			Vector string  `json:"vector_string"`
			Score  float64 `json:"score"`
		} `json:"cvss_v4"`
	} `json:"cvss_severities"`
	CWEs []struct {
		ID string `json:"cwe_id"`
	} `json:"cwes"`
	Vulnerabilities []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		FirstPatchedVersion string `json:"first_patched_version"`
	} `json:"vulnerabilities"`
}

// Query returns reviewed GitHub advisories keyed by the requested GHSA or CVE identifier.
func (c Client) Query(ctx context.Context, ids []string) (map[string]Record, error) {
	out := map[string]Record{}
	ids = unique(ids)
	if len(ids) == 0 {
		return out, nil
	}
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = "https://api.github.com"
	}
	hc := c.HTTPClient
	if hc == nil {
		hc = httpclient.New(15 * time.Second)
	}

	var mu sync.Mutex
	var group errgroup.Group
	// Limit goroutine creation as well as HTTP concurrency so unusually large
	// advisory sets cannot accumulate one blocked goroutine per identifier.
	group.SetLimit(maxConcurrentAdvisoryRequests)
	for _, id := range ids {
		id := id
		group.Go(func() error {
			record, ok, err := c.queryOne(ctx, hc, base, id)
			if err != nil {
				return err
			}
			if ok {
				mu.Lock()
				out[id] = record
				mu.Unlock()
			}
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	return out, nil
}

// queryOne retrieves and normalizes one GHSA or CVE identifier.
func (c Client) queryOne(ctx context.Context, hc *http.Client, base, id string) (Record, bool, error) {
	var advisories []apiAdvisory
	switch {
	case strings.HasPrefix(id, "GHSA-"):
		var a apiAdvisory
		if err := c.getJSON(ctx, hc, base+"/advisories/"+url.PathEscape(id), &a); err != nil {
			return Record{}, false, fmt.Errorf("GitHub advisory %s: %w", id, err)
		}
		advisories = []apiAdvisory{a}
	case strings.HasPrefix(id, "CVE-"):
		u, _ := url.Parse(base + "/advisories")
		q := u.Query()
		q.Set("cve_id", id)
		q.Set("ecosystem", "go")
		q.Set("type", "reviewed")
		q.Set("per_page", "100")
		u.RawQuery = q.Encode()
		if err := c.getJSON(ctx, hc, u.String(), &advisories); err != nil {
			return Record{}, false, fmt.Errorf("GitHub advisory %s: %w", id, err)
		}
	default:
		return Record{}, false, nil
	}
	for _, a := range advisories {
		if a.Type != "" && a.Type != "reviewed" {
			continue
		}
		return normalize(a), true, nil
	}
	return Record{}, false, nil
}

// getJSON performs one authenticated GitHub API request and decodes its JSON body.
func (c Client) getJSON(ctx context.Context, hc *http.Client, endpoint string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	req.Header.Set("User-Agent", "goscan")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return httpjson.Decode(resp.Body, dst)
}

// normalize converts GitHub's API shape into the scanner's enrichment record.
func normalize(a apiAdvisory) Record {
	r := Record{
		GHSAID:           a.GHSAID,
		CVEID:            a.CVEID,
		Summary:          a.Summary,
		Description:      a.Description,
		Severity:         parseSeverity(a.Severity),
		References:       unique(a.References),
		FirstPatchedByGo: map[string]string{},
	}
	for _, cwe := range a.CWEs {
		if cwe.ID != "" {
			r.CWEs = append(r.CWEs, cwe.ID)
		}
	}
	r.CWEs = unique(r.CWEs)
	for _, v := range a.Vulnerabilities {
		if strings.EqualFold(v.Package.Ecosystem, "go") && v.Package.Name != "" && v.FirstPatchedVersion != "" {
			version := goversion.NormalizeForGo(v.FirstPatchedVersion)
			current := r.FirstPatchedByGo[v.Package.Name]
			if current == "" || goversion.Compare(version, current) < 0 {
				r.FirstPatchedByGo[v.Package.Name] = version
			}
		}
	}
	if a.CVSSSeverities.V4.Score > 0 {
		r.CVSS = &model.CVSS{Version: "4.0", Vector: a.CVSSSeverities.V4.Vector, Score: a.CVSSSeverities.V4.Score, Source: string(model.SourceGitHub)}
	}
	// Retain the highest available score rather than assuming the newest CVSS
	// version is necessarily the most severe representation.
	if a.CVSSSeverities.V3.Score > 0 && (r.CVSS == nil || a.CVSSSeverities.V3.Score > r.CVSS.Score) {
		r.CVSS = &model.CVSS{Version: cvssVersion(a.CVSSSeverities.V3.Vector, "3.x"), Vector: a.CVSSSeverities.V3.Vector, Score: a.CVSSSeverities.V3.Score, Source: string(model.SourceGitHub)}
	}
	return r
}

// cvssVersion extracts the version component from a CVSS vector.
func cvssVersion(vector, fallback string) string {
	if after, ok := strings.CutPrefix(vector, "CVSS:"); ok {
		if rest := after; rest != "" {
			if version, _, ok := strings.Cut(rest, "/"); ok {
				return version
			}
		}
	}
	return fallback
}

// parseSeverity maps GitHub severity labels to normalized model values.
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

// unique removes empty and duplicate strings and returns a sorted result.
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
