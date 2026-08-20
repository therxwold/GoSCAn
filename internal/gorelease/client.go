package gorelease

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

// Client queries the official Go downloads service for stable releases.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

// Release describes the newest stable Go toolchain and its language version.
type Release struct {
	Version         string `json:"version"`
	LanguageVersion string `json:"language_version"`
}

type apiRelease struct {
	Version string `json:"version"`
	Stable  bool   `json:"stable"`
}

// Latest returns the newest stable Go release published by go.dev.
func (c Client) Latest(ctx context.Context) (Release, error) {
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = "https://go.dev"
	}
	hc := c.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/dl/?mode=json", nil)
	if err != nil {
		return Release{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "goscan")
	resp, err := hc.Do(req)
	if err != nil {
		return Release{}, fmt.Errorf("query Go releases: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Release{}, fmt.Errorf("query Go releases: HTTP %d", resp.StatusCode)
	}
	var releases []apiRelease
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return Release{}, fmt.Errorf("decode Go releases: %w", err)
	}
	var newest string
	for _, release := range releases {
		if !release.Stable || !strings.HasPrefix(release.Version, "go1.") {
			continue
		}
		if _, ok := LanguageVersion(release.Version); !ok {
			continue
		}
		if newest == "" || ToolchainCompare(release.Version, newest) > 0 {
			newest = release.Version
		}
	}
	if newest == "" {
		return Release{}, fmt.Errorf("Go releases response did not contain a stable release")
	}
	language, _ := LanguageVersion(newest)
	return Release{Version: newest, LanguageVersion: language}, nil
}

// LanguageVersion converts a toolchain release such as go1.26.6 to the go directive version 1.26.
func LanguageVersion(toolchain string) (string, bool) {
	v := strings.TrimPrefix(strings.TrimSpace(toolchain), "go")
	canonical := "v" + v
	if !semver.IsValid(canonical) {
		return "", false
	}
	majorMinor := strings.TrimPrefix(semver.MajorMinor(canonical), "v")
	if majorMinor == "" {
		return "", false
	}
	return majorMinor, true
}

// ToolchainCompare compares Go toolchain names such as go1.25.4 and go1.26.6.
func ToolchainCompare(a, b string) int {
	a = strings.TrimPrefix(strings.TrimSpace(a), "go")
	b = strings.TrimPrefix(strings.TrimSpace(b), "go")
	if a == b {
		return 0
	}
	av, bv := "v"+a, "v"+b
	if semver.IsValid(av) && semver.IsValid(bv) {
		return semver.Compare(av, bv)
	}
	return strings.Compare(a, b)
}

// LanguageCompare compares go directive versions using only their semantic versions.
func LanguageCompare(a, b string) int {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == b {
		return 0
	}
	av, bv := "v"+a, "v"+b
	if semver.IsValid(av) && semver.IsValid(bv) {
		return semver.Compare(av, bv)
	}
	return strings.Compare(a, b)
}

// Supported reports whether current belongs to one of the two newest Go major release lines.
func Supported(current, latest string) bool {
	curMajor, curMinor, ok := majorMinor(current)
	if !ok {
		return false
	}
	latestMajor, latestMinor, ok := majorMinor(latest)
	if !ok || curMajor != latestMajor {
		return false
	}
	return curMinor >= latestMinor-1
}

func majorMinor(v string) (int, int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "go")
	var major, minor int
	if _, err := fmt.Sscanf(v, "%d.%d", &major, &minor); err != nil {
		return 0, 0, false
	}
	return major, minor, true
}
