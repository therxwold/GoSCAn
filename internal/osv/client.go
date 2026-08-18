package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/therxwold/GoSCAn/internal/cvss"
	"github.com/therxwold/GoSCAn/internal/goversion"
	"github.com/therxwold/GoSCAn/internal/model"
)

// Client queries OSV for vulnerabilities affecting selected Go module versions.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

// Target identifies one selected Go module version to query in OSV.
type Target struct {
	Key     string
	Path    string
	Version string
}

type query struct {
	Version   string       `json:"version,omitempty"`
	Package   queryPackage `json:"package"`
	PageToken string       `json:"page_token,omitempty"`
}

type queryPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type batchRequest struct {
	Queries []query `json:"queries"`
}

type batchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
		NextPageToken string `json:"next_page_token"`
	} `json:"results"`
}

// Record represents the OSV advisory fields used by GoSCAn.
type Record struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Severity []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		} `json:"severity"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced,omitempty"`
				Fixed        string `json:"fixed,omitempty"`
				LastAffected string `json:"last_affected,omitempty"`
				Limit        string `json:"limit,omitempty"`
			} `json:"events"`
		} `json:"ranges"`
		Versions []string `json:"versions"`
	} `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	DatabaseSpecific map[string]any `json:"database_specific"`
}

// Query scans targets through OSV and groups alias records into one finding per vulnerability.
func (c Client) Query(ctx context.Context, targets []Target) (map[string][]model.Vulnerability, error) {
	if len(targets) == 0 {
		return map[string][]model.Vulnerability{}, nil
	}
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = "https://api.osv.dev"
	}
	hc := c.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}

	idsByTarget := make(map[string][]string, len(targets))
	pending := append([]Target(nil), targets...)
	pageTokens := map[string]string{}
	for len(pending) > 0 {
		reqPayload := batchRequest{Queries: make([]query, 0, len(pending))}
		for _, t := range pending {
			reqPayload.Queries = append(reqPayload.Queries, query{
				Version:   strings.TrimPrefix(t.Version, "v"),
				Package:   queryPackage{Name: t.Path, Ecosystem: "Go"},
				PageToken: pageTokens[t.Key],
			})
		}
		var resp batchResponse
		if err := doJSON(ctx, hc, http.MethodPost, base+"/v1/querybatch", reqPayload, &resp); err != nil {
			return nil, fmt.Errorf("OSV query: %w", err)
		}
		if len(resp.Results) != len(pending) {
			return nil, fmt.Errorf("OSV query returned %d results for %d inputs", len(resp.Results), len(pending))
		}
		next := make([]Target, 0)
		for i, result := range resp.Results {
			t := pending[i]
			for _, v := range result.Vulns {
				idsByTarget[t.Key] = appendUnique(idsByTarget[t.Key], v.ID)
			}
			if result.NextPageToken != "" {
				pageTokens[t.Key] = result.NextPageToken
				next = append(next, t)
			}
		}
		pending = next
	}

	uniqueIDs := map[string]struct{}{}
	for _, ids := range idsByTarget {
		for _, id := range ids {
			uniqueIDs[id] = struct{}{}
		}
	}
	records, err := fetchRecords(ctx, hc, base, uniqueIDs)
	if err != nil {
		return nil, err
	}

	out := make(map[string][]model.Vulnerability, len(targets))
	for _, t := range targets {
		var rs []Record
		for _, id := range idsByTarget[t.Key] {
			if r, ok := records[id]; ok {
				rs = append(rs, r)
			}
		}
		groups := groupAliases(rs)
		for _, group := range groups {
			out[t.Key] = append(out[t.Key], mergeGroup(t.Path, t.Version, group))
		}
		sort.Slice(out[t.Key], func(i, j int) bool { return out[t.Key][i].ID < out[t.Key][j].ID })
	}
	return out, nil
}

func fetchRecords(ctx context.Context, hc *http.Client, base string, ids map[string]struct{}) (map[string]Record, error) {
	out := make(map[string]Record, len(ids))
	var mu sync.Mutex
	var firstErr error
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for id := range ids {
		id := id
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			var r Record
			endpoint := base + "/v1/vulns/" + url.PathEscape(id)
			if err := doJSON(ctx, hc, http.MethodGet, endpoint, nil, &r); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("fetch OSV %s: %w", id, err)
				}
				mu.Unlock()
				return
			}
			mu.Lock()
			out[id] = r
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out, firstErr
}

func doJSON(ctx context.Context, hc *http.Client, method, endpoint string, body any, dst any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return json.NewDecoder(resp.Body).Decode(dst)
}

func groupAliases(records []Record) [][]Record {
	var groups [][]Record
	for _, r := range records {
		ids := identifierSet(r)
		matches := []int{}
		for i, g := range groups {
			if groupIntersects(g, ids) {
				matches = append(matches, i)
			}
		}
		if len(matches) == 0 {
			groups = append(groups, []Record{r})
			continue
		}
		base := matches[0]
		groups[base] = append(groups[base], r)
		for i := len(matches) - 1; i >= 1; i-- {
			idx := matches[i]
			groups[base] = append(groups[base], groups[idx]...)
			groups = append(groups[:idx], groups[idx+1:]...)
		}
	}
	return groups
}

func groupIntersects(group []Record, ids map[string]struct{}) bool {
	for _, r := range group {
		for id := range identifierSet(r) {
			if _, ok := ids[id]; ok {
				return true
			}
		}
	}
	return false
}

func identifierSet(r Record) map[string]struct{} {
	m := map[string]struct{}{r.ID: {}}
	for _, a := range r.Aliases {
		m[a] = struct{}{}
	}
	return m
}

func mergeGroup(modulePath, current string, records []Record) model.Vulnerability {
	sort.SliceStable(records, func(i, j int) bool { return idPreference(records[i].ID) < idPreference(records[j].ID) })
	primary := records[0]
	ids := map[string]struct{}{}
	var cves []string
	var refs []string
	fixed := ""
	severity := model.SeverityUnknown
	var bestCVSS *model.CVSS
	for _, r := range records {
		ids[r.ID] = struct{}{}
		for _, a := range r.Aliases {
			ids[a] = struct{}{}
		}
		if f := fixedVersion(r, modulePath, current); f != "" {
			f = goversion.NormalizeForGo(f)
			if fixed == "" || goversion.Compare(f, fixed) < 0 {
				fixed = f
			}
		}
		if s := severityFromDatabaseSpecific(r.DatabaseSpecific); s.Rank() > severity.Rank() {
			severity = s
		}
		if c := bestCVSSForRecord(r, modulePath); c != nil && (bestCVSS == nil || c.Score > bestCVSS.Score) {
			bestCVSS = c
		}
		for _, ref := range r.References {
			if ref.URL != "" {
				refs = appendUnique(refs, ref.URL)
			}
		}
	}
	allIDs := make([]string, 0, len(ids))
	for id := range ids {
		if strings.HasPrefix(id, "CVE-") {
			cves = append(cves, id)
		}
		if id != primary.ID {
			allIDs = append(allIDs, id)
		}
	}
	sort.Strings(allIDs)
	sort.Strings(cves)
	sort.Strings(refs)
	if bestCVSS != nil {
		severity = severityFromScore(bestCVSS.Score)
	}
	return model.Vulnerability{
		ID: primary.ID, Aliases: allIDs, Summary: primary.Summary, Details: primary.Details,
		CVEs: cves, Fixed: fixed, CVSS: bestCVSS, Severity: severity, References: refs,
	}
}

func fixedVersion(r Record, modulePath, current string) string {
	cur := strings.TrimPrefix(current, "v")
	best := ""
	for _, a := range r.Affected {
		if a.Package.Ecosystem != "Go" || a.Package.Name != modulePath {
			continue
		}
		for _, rg := range a.Ranges {
			if rg.Type != "SEMVER" && rg.Type != "ECOSYSTEM" {
				continue
			}
			introduced := "0"
			for _, ev := range rg.Events {
				switch {
				case ev.Introduced != "":
					introduced = ev.Introduced
				case ev.Fixed != "":
					if goversion.Compare(cur, introduced) >= 0 && goversion.Compare(cur, ev.Fixed) < 0 {
						if best == "" || goversion.Compare(ev.Fixed, best) < 0 {
							best = ev.Fixed
						}
					}
					introduced = ""
				case ev.LastAffected != "", ev.Limit != "":
					introduced = ""
				}
			}
		}
	}
	return best
}

func bestCVSSForRecord(r Record, modulePath string) *model.CVSS {
	type sev struct{ Type, Score string }
	var candidates []sev
	for _, s := range r.Severity {
		candidates = append(candidates, sev{s.Type, s.Score})
	}
	for _, a := range r.Affected {
		if a.Package.Name != modulePath {
			continue
		}
		for _, s := range a.Severity {
			candidates = append(candidates, sev{s.Type, s.Score})
		}
	}
	var best *model.CVSS
	for _, s := range candidates {
		if s.Type != "CVSS_V2" && s.Type != "CVSS_V3" && s.Type != "CVSS_V4" {
			continue
		}
		score, version, err := cvss.Score(s.Score)
		if err != nil {
			continue
		}
		c := &model.CVSS{Version: version, Vector: s.Score, Score: score}
		if best == nil || c.Score > best.Score {
			best = c
		}
	}
	return best
}

func severityFromDatabaseSpecific(m map[string]any) model.Severity {
	v, _ := m["severity"].(string)
	switch strings.ToLower(v) {
	case "critical":
		return model.SeverityCritical
	case "high":
		return model.SeverityHigh
	case "moderate", "medium":
		return model.SeverityMedium
	case "low":
		return model.SeverityLow
	default:
		return model.SeverityUnknown
	}
}

func severityFromScore(score float64) model.Severity {
	switch {
	case score >= 9:
		return model.SeverityCritical
	case score >= 7:
		return model.SeverityHigh
	case score >= 4:
		return model.SeverityMedium
	case score > 0:
		return model.SeverityLow
	default:
		return model.SeverityUnknown
	}
}

func idPreference(id string) int {
	switch {
	case strings.HasPrefix(id, "CVE-"):
		return 0
	case strings.HasPrefix(id, "GO-"):
		return 1
	case strings.HasPrefix(id, "GHSA-"):
		return 2
	default:
		return 3
	}
}

func appendUnique(in []string, v string) []string {
	for _, x := range in {
		if x == v {
			return in
		}
	}
	return append(in, v)
}
