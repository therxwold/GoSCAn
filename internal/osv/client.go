package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/therxwold/GoSCAn/internal/cvss"
	"github.com/therxwold/GoSCAn/internal/goversion"
	"github.com/therxwold/GoSCAn/internal/httpclient"
	"github.com/therxwold/GoSCAn/internal/httpjson"
	"github.com/therxwold/GoSCAn/internal/model"
	"golang.org/x/sync/errgroup"
)

// maxConcurrentRecordRequests bounds OSV detail lookups and worker allocation.
const maxConcurrentRecordRequests = 8

// Client queries OSV for vulnerabilities affecting selected Go module versions.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

// Target identifies one selected Go module version to query in OSV.
type Target struct {
	Key           string
	Path          string
	Version       string
	Packages      []string
	PackagesKnown bool
}

// query is one module-version request in an OSV batch query.
type query struct {
	Version   string       `json:"version,omitempty"`
	Package   queryPackage `json:"package"`
	PageToken string       `json:"page_token,omitempty"`
}

// queryPackage identifies an ecosystem package in an OSV request.
type queryPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// batchRequest is the request envelope for OSV's batch endpoint.
type batchRequest struct {
	Queries []query `json:"queries"`
}

// batchResponse models paginated vulnerability identifiers returned per query.
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
		Versions          []string `json:"versions"`
		EcosystemSpecific struct {
			Imports []struct {
				Path    string   `json:"path"`
				Symbols []string `json:"symbols"`
			} `json:"imports"`
		} `json:"ecosystem_specific"`
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
		hc = httpclient.New(20 * time.Second)
	}

	idsByTarget := make(map[string][]string, len(targets))
	pending := append([]Target(nil), targets...)
	pageTokens := map[string]string{}
	// OSV paginates each batch element independently, so only targets carrying a
	// next-page token are sent in the following batch.
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
			// Package metadata can eliminate module-level false positives only when
			// package loading completed successfully.
			if !groupAffectsPackages(t, group) {
				continue
			}
			out[t.Key] = append(out[t.Key], mergeGroup(t.Path, t.Version, group))
		}
		sort.Slice(out[t.Key], func(i, j int) bool { return out[t.Key][i].ID < out[t.Key][j].ID })
	}
	return out, nil
}

// groupAffectsPackages uses the Go vulnerability database's affected import
// paths when package loading succeeded. Records without package-level metadata
// remain reportable so non-Go OSV records are handled conservatively.
func groupAffectsPackages(target Target, records []Record) bool {
	if !target.PackagesKnown {
		return true
	}
	loaded := make(map[string]struct{}, len(target.Packages))
	for _, pkg := range target.Packages {
		loaded[pkg] = struct{}{}
	}
	hasImportMetadata := false
	for _, record := range records {
		for _, affected := range record.Affected {
			if affected.Package.Ecosystem != "Go" || affected.Package.Name != target.Path {
				continue
			}
			for _, imported := range affected.EcosystemSpecific.Imports {
				hasImportMetadata = true
				if _, ok := loaded[imported.Path]; ok {
					return true
				}
			}
		}
	}
	return !hasImportMetadata
}

// fetchRecords concurrently retrieves complete OSV records for advisory identifiers.
func fetchRecords(ctx context.Context, hc *http.Client, base string, ids map[string]struct{}) (map[string]Record, error) {
	out := make(map[string]Record, len(ids))
	var mu sync.Mutex
	var group errgroup.Group
	// SetLimit bounds both live requests and allocated worker goroutines. A
	// semaphore inside one goroutine per advisory would still allow a very large
	// response to allocate unbounded waiting goroutines.
	group.SetLimit(maxConcurrentRecordRequests)
	for id := range ids {
		id := id
		group.Go(func() error {
			var r Record
			endpoint := base + "/v1/vulns/" + url.PathEscape(id)
			if err := doJSON(ctx, hc, http.MethodGet, endpoint, nil, &r); err != nil {
				return fmt.Errorf("fetch OSV %s: %w", id, err)
			}
			mu.Lock()
			out[id] = r
			mu.Unlock()
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	return out, nil
}

// doJSON performs one OSV JSON request and decodes a successful response.
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
	return httpjson.Decode(resp.Body, dst)
}

// groupAliases joins records connected through any shared advisory identifier.
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

// groupIntersects reports whether a record group shares any identifier with ids.
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

// identifierSet returns the primary ID and aliases associated with an OSV record.
func identifierSet(r Record) map[string]struct{} {
	m := map[string]struct{}{r.ID: {}}
	for _, a := range r.Aliases {
		m[a] = struct{}{}
	}
	return m
}

// mergeGroup normalizes one alias-connected OSV group into a single vulnerability.
func mergeGroup(modulePath, current string, records []Record) model.Vulnerability {
	sort.SliceStable(records, func(i, j int) bool { return idPreference(records[i].ID) < idPreference(records[j].ID) })
	primary := records[0]
	ids := map[string]struct{}{}
	var cves []string
	var refs []string
	imports := map[string][]string{}
	fixed := ""
	severity := model.SeverityUnknown
	var bestCVSS *model.CVSS
	for _, r := range records {
		ids[r.ID] = struct{}{}
		for _, a := range r.Aliases {
			ids[a] = struct{}{}
		}
		// Alias records may expose different ranges; choose the earliest fix that
		// closes the range containing the selected version.
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
		for _, affected := range r.Affected {
			if affected.Package.Ecosystem != "Go" || affected.Package.Name != modulePath {
				continue
			}
			for _, imported := range affected.EcosystemSpecific.Imports {
				for _, symbol := range imported.Symbols {
					imports[imported.Path] = appendUnique(imports[imported.Path], symbol)
				}
				if _, ok := imports[imported.Path]; !ok {
					imports[imported.Path] = nil
				}
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
	affectedImports := make([]model.AffectedImport, 0, len(imports))
	for path, symbols := range imports {
		sort.Strings(symbols)
		affectedImports = append(affectedImports, model.AffectedImport{Path: path, Symbols: symbols})
	}
	sort.Slice(affectedImports, func(i, j int) bool { return affectedImports[i].Path < affectedImports[j].Path })
	return model.Vulnerability{
		ID: primary.ID, Aliases: allIDs, Summary: primary.Summary, Details: primary.Details,
		CVEs: cves, Fixed: fixed, CVSS: bestCVSS, Severity: severity, References: refs,
		Sources: []model.AdvisorySource{model.SourceOSV}, AffectedImports: affectedImports,
	}
}

// fixedVersion returns the earliest fix closing the vulnerable range containing current.
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

// bestCVSSForRecord returns the highest valid CVSS score applicable to modulePath.
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
		c := &model.CVSS{Version: version, Vector: s.Score, Score: score, Source: string(model.SourceOSV)}
		if best == nil || c.Score > best.Score {
			best = c
		}
	}
	return best
}

// severityFromDatabaseSpecific normalizes OSV database-specific severity metadata.
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

// severityFromScore maps a CVSS base score to the normalized severity bands.
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

// idPreference ranks Go, GHSA, CVE, and unknown IDs for canonical selection.
func idPreference(id string) int {
	switch {
	case strings.HasPrefix(id, "GO-"):
		return 0
	case strings.HasPrefix(id, "GHSA-"):
		return 1
	case strings.HasPrefix(id, "CVE-"):
		return 2
	default:
		return 3
	}
}

// appendUnique adds v only when it is not already present.
func appendUnique(in []string, v string) []string {
	if slices.Contains(in, v) {
		return in
	}
	return append(in, v)
}
