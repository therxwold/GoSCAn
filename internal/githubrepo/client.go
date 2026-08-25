package githubrepo

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/therxwold/GoSCAn/internal/httpjson"
	"golang.org/x/sync/errgroup"
)

// maxConcurrentRepositoryRequests bounds GitHub API pressure and worker allocation.
const maxConcurrentRepositoryRequests = 6

// Client queries GitHub repository metadata used for dependency maintenance health checks.
type Client struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

// Record contains maintenance metadata for one GitHub repository.
type Record struct {
	Repository           string    `json:"repository"`
	URL                  string    `json:"url,omitempty"`
	Archived             bool      `json:"archived,omitempty"`
	PushedAt             time.Time `json:"pushed_at,omitempty"`
	ExplicitUnmaintained bool      `json:"explicit_unmaintained,omitempty"`
	MaintenanceNotice    string    `json:"maintenance_notice,omitempty"`
}

// apiRepository models GitHub repository metadata used by health checks.
type apiRepository struct {
	FullName string    `json:"full_name"`
	HTMLURL  string    `json:"html_url"`
	Archived bool      `json:"archived"`
	PushedAt time.Time `json:"pushed_at"`
}

// apiReadme models the encoded README response returned by GitHub.
type apiReadme struct {
	Encoding string `json:"encoding"`
	Content  string `json:"content"`
}

// Query returns repository health records keyed by GitHub repository root (owner/repo).
// README maintenance notices are inspected only for repositories older than readmeCutoff.
func (c Client) Query(ctx context.Context, modulePaths []string, readmeCutoff time.Time) (map[string]Record, error) {
	repos := uniqueRepositories(modulePaths)
	out := make(map[string]Record, len(repos))
	if len(repos) == 0 {
		return out, nil
	}
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = "https://api.github.com"
	}
	hc := c.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}

	var mu sync.Mutex
	var group errgroup.Group
	// Bound allocated workers as well as requests for enterprise-sized graphs.
	group.SetLimit(maxConcurrentRepositoryRequests)
	for _, repo := range repos {
		repo := repo
		group.Go(func() error {
			record, err := c.queryOne(ctx, hc, base, repo, readmeCutoff)
			if err != nil {
				return err
			}
			mu.Lock()
			out[repo] = record
			mu.Unlock()
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	return out, nil
}

// queryOne retrieves repository metadata and inspects stale repositories for maintenance notices.
func (c Client) queryOne(ctx context.Context, hc *http.Client, base, repo string, readmeCutoff time.Time) (Record, error) {
	var metadata apiRepository
	if err := c.getJSON(ctx, hc, base+"/repos/"+repo, &metadata); err != nil {
		return Record{}, fmt.Errorf("GitHub repository %s: %w", repo, err)
	}
	record := Record{Repository: repo, URL: metadata.HTMLURL, Archived: metadata.Archived, PushedAt: metadata.PushedAt}
	// README inspection is reserved for stale repositories to limit API traffic
	// and avoid interpreting ordinary prose as a maintenance signal unnecessarily.
	if metadata.Archived || metadata.PushedAt.IsZero() || (!readmeCutoff.IsZero() && metadata.PushedAt.After(readmeCutoff)) {
		return record, nil
	}
	var readme apiReadme
	status, err := c.getJSONStatus(ctx, hc, base+"/repos/"+repo+"/readme", &readme)
	if err != nil {
		return Record{}, fmt.Errorf("GitHub repository %s README: %w", repo, err)
	}
	if status == http.StatusNotFound {
		return record, nil
	}
	if strings.EqualFold(readme.Encoding, "base64") {
		decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(readme.Content, "\n", ""))
		if err == nil {
			if notice := maintenanceNotice(string(decoded)); notice != "" {
				record.ExplicitUnmaintained = true
				record.MaintenanceNotice = notice
			}
		}
	}
	return record, nil
}

// getJSON decodes a successful GitHub response and rejects non-2xx statuses.
func (c Client) getJSON(ctx context.Context, hc *http.Client, endpoint string, dst any) error {
	status, err := c.getJSONStatus(ctx, hc, endpoint, dst)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("HTTP %d", status)
	}
	return nil
}

// getJSONStatus performs one GitHub request and returns its HTTP status with decoded data.
func (c Client) getJSONStatus(ctx context.Context, hc *http.Client, endpoint string, dst any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	req.Header.Set("User-Agent", "goscan")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return resp.StatusCode, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := httpjson.Decode(resp.Body, dst); err != nil {
		return resp.StatusCode, err
	}
	return resp.StatusCode, nil
}

// RepositoryFromModule returns the owner/repository root for a github.com module path.
func RepositoryFromModule(modulePath string) (string, bool) {
	parts := strings.Split(strings.TrimSpace(modulePath), "/")
	if len(parts) < 3 || !strings.EqualFold(parts[0], "github.com") || parts[1] == "" || parts[2] == "" {
		return "", false
	}
	return url.PathEscape(parts[1]) + "/" + url.PathEscape(parts[2]), true
}

// uniqueRepositories derives unique GitHub owner/repository identifiers from module paths.
func uniqueRepositories(modulePaths []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, modulePath := range modulePaths {
		repo, ok := RepositoryFromModule(modulePath)
		if !ok || seen[repo] {
			continue
		}
		seen[repo] = true
		out = append(out, repo)
	}
	return out
}

// maintenanceNotice returns the first explicit unmaintained phrase found in a README.
func maintenanceNotice(readme string) string {
	lower := strings.ToLower(readme)
	phrases := []string{
		"no longer maintained",
		"not actively maintained",
		"not maintained",
		"this project is unmaintained",
		"this repository is unmaintained",
		"project is deprecated and unmaintained",
	}
	for _, phrase := range phrases {
		if strings.Contains(lower, phrase) {
			return phrase
		}
	}
	return ""
}
