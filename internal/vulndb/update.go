package vulndb

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// DefaultURL is the official Go vulnerability database snapshot.
	DefaultURL = "https://vuln.go.dev/vulndb.zip"
	// maxDownloadSize bounds compressed input retained on disk.
	maxDownloadSize = 128 << 20
	// maxExtractedSize bounds the total declared size of archive entries.
	maxExtractedSize = 512 << 20
)

// Metadata describes an installed Go vulnerability database snapshot.
type Metadata struct {
	// Source identifies the snapshot URL without credentials or query parameters.
	Source string `json:"source"`
	// DownloadedAt records when GoSCAn fetched the snapshot.
	DownloadedAt time.Time `json:"downloaded_at"`
	// Modified is the upstream database modification timestamp.
	Modified time.Time `json:"modified"`
	// Advisories is the number of validated GO advisory records.
	Advisories int `json:"advisories"`
	// Path is the installed directory and is omitted from persisted metadata.
	Path string `json:"-"`
}

// Updater downloads and atomically installs Go vulnerability database snapshots.
type Updater struct {
	// Client optionally overrides the HTTP client used for downloads.
	Client *http.Client
	// URL optionally overrides DefaultURL.
	URL string
	// Now optionally supplies a clock for deterministic callers and tests.
	Now func() time.Time
}

// DefaultPath returns GoSCAn's platform-specific vulnerability database directory.
func DefaultPath() (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locate user cache: %w", err)
	}
	return filepath.Join(cache, "goscan", "vulndb"), nil
}

// DatabaseURL converts a local database directory to a file URL accepted by govulncheck.
// Existing HTTP and file URLs are returned unchanged.
func DatabaseURL(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("parse vulnerability database location: %w", err)
	}
	if parsed.Scheme != "" {
		switch parsed.Scheme {
		case "file", "http", "https":
			return value, nil
		default:
			return "", fmt.Errorf("unsupported vulnerability database URL scheme %q", parsed.Scheme)
		}
	}
	abs, err := filepath.Abs(value)
	if err != nil {
		return "", fmt.Errorf("resolve vulnerability database path: %w", err)
	}
	return (&url.URL{Scheme: "file", Path: filepath.ToSlash(abs)}).String(), nil
}

// Installed reports whether path contains the required database indexes.
func Installed(path string) bool {
	for _, name := range []string{"index/db.json", "index/modules.json", "index/vulns.json"} {
		info, err := os.Stat(filepath.Join(path, filepath.FromSlash(name)))
		if err != nil || !info.Mode().IsRegular() {
			return false
		}
	}
	return true
}

// Update downloads, validates, and atomically replaces the database at destination.
func (u Updater) Update(ctx context.Context, destination string) (Metadata, error) {
	destination, err := safeDestination(destination)
	if err != nil {
		return Metadata{}, err
	}
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return Metadata{}, fmt.Errorf("create database parent: %w", err)
	}

	archive, err := os.CreateTemp(parent, ".vulndb-*.zip")
	if err != nil {
		return Metadata{}, fmt.Errorf("create temporary database archive: %w", err)
	}
	archivePath := archive.Name()
	defer os.Remove(archivePath)

	if err := u.download(ctx, archive); err != nil {
		archive.Close()
		return Metadata{}, err
	}
	if err := archive.Close(); err != nil {
		return Metadata{}, fmt.Errorf("close database archive: %w", err)
	}

	staging, err := os.MkdirTemp(parent, ".vulndb-staging-*")
	if err != nil {
		return Metadata{}, fmt.Errorf("create database staging directory: %w", err)
	}
	keepStaging := false
	defer func() {
		if !keepStaging {
			os.RemoveAll(staging)
		}
	}()

	advisories, err := extract(archivePath, staging)
	if err != nil {
		return Metadata{}, err
	}
	modified, err := validate(staging, advisories)
	if err != nil {
		return Metadata{}, err
	}

	now := time.Now
	if u.Now != nil {
		now = u.Now
	}
	metadata := Metadata{
		Source: publicSourceURL(u.sourceURL()), DownloadedAt: now().UTC(), Modified: modified,
		Advisories: advisories, Path: destination,
	}
	metadataData, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return Metadata{}, fmt.Errorf("encode database metadata: %w", err)
	}
	metadataData = append(metadataData, '\n')
	if err := os.WriteFile(filepath.Join(staging, ".goscan.json"), metadataData, 0o644); err != nil {
		return Metadata{}, fmt.Errorf("write database metadata: %w", err)
	}

	if err := install(staging, destination); err != nil {
		return Metadata{}, err
	}
	keepStaging = true
	return metadata, nil
}

// publicSourceURL removes credentials and query parameters before persistence or display.
func publicSourceURL(value string) string {
	parsed, err := url.Parse(value)
	if err != nil {
		return value
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

// sourceURL returns the configured source or the official snapshot URL.
func (u Updater) sourceURL() string {
	if strings.TrimSpace(u.URL) != "" {
		return strings.TrimSpace(u.URL)
	}
	return DefaultURL
}

// download writes a size-limited database snapshot to dst.
func (u Updater) download(ctx context.Context, dst *os.File) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.sourceURL(), nil)
	if err != nil {
		return fmt.Errorf("create database request: %w", err)
	}
	req.Header.Set("User-Agent", "GoSCAn vulnerability database updater")
	client := u.Client
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download vulnerability database: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download vulnerability database: server returned %s", resp.Status)
	}
	if resp.ContentLength > maxDownloadSize {
		return fmt.Errorf("download vulnerability database: archive exceeds %d bytes", maxDownloadSize)
	}

	written, err := io.Copy(dst, io.LimitReader(resp.Body, maxDownloadSize+1))
	if err != nil {
		return fmt.Errorf("download vulnerability database: %w", err)
	}
	if written > maxDownloadSize {
		return fmt.Errorf("download vulnerability database: archive exceeds %d bytes", maxDownloadSize)
	}
	if err := dst.Sync(); err != nil {
		return fmt.Errorf("sync database archive: %w", err)
	}
	return nil
}

// safeDestination resolves destination and rejects filesystem roots.
func safeDestination(destination string) (string, error) {
	if strings.TrimSpace(destination) == "" {
		return "", fmt.Errorf("database destination cannot be empty")
	}
	abs, err := filepath.Abs(destination)
	if err != nil {
		return "", fmt.Errorf("resolve database destination: %w", err)
	}
	if filepath.Dir(abs) == abs {
		return "", fmt.Errorf("database destination cannot be a filesystem root")
	}
	return filepath.Clean(abs), nil
}

// extract safely expands archivePath into destination and returns the advisory count.
func extract(archivePath, destination string) (int, error) {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return 0, fmt.Errorf("open vulnerability database archive: %w", err)
	}
	defer reader.Close()

	var total uint64
	advisories := 0
	for _, entry := range reader.File {
		name := filepath.Clean(filepath.FromSlash(entry.Name))
		if name == "." || filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			return 0, fmt.Errorf("invalid archive path %q", entry.Name)
		}
		if entry.Mode()&os.ModeSymlink != 0 || (!entry.FileInfo().IsDir() && !entry.Mode().IsRegular()) {
			return 0, fmt.Errorf("unsupported archive entry %q", entry.Name)
		}
		total += entry.UncompressedSize64
		if total > maxExtractedSize {
			return 0, fmt.Errorf("vulnerability database exceeds %d extracted bytes", maxExtractedSize)
		}

		target := filepath.Join(destination, name)
		if entry.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return 0, fmt.Errorf("create archive directory %q: %w", entry.Name, err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return 0, fmt.Errorf("create archive parent %q: %w", entry.Name, err)
		}
		if err := extractFile(entry, target); err != nil {
			return 0, err
		}
		if strings.HasPrefix(entry.Name, "ID/GO-") && strings.HasSuffix(entry.Name, ".json") {
			advisories++
		}
	}
	return advisories, nil
}

// extractFile copies one regular zip entry to target.
func extractFile(entry *zip.File, target string) error {
	src, err := entry.Open()
	if err != nil {
		return fmt.Errorf("open archive entry %q: %w", entry.Name, err)
	}
	defer src.Close()
	dst, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("create archive entry %q: %w", entry.Name, err)
	}
	_, copyErr := io.Copy(dst, src)
	closeErr := dst.Close()
	if copyErr != nil {
		return fmt.Errorf("extract archive entry %q: %w", entry.Name, copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close archive entry %q: %w", entry.Name, closeErr)
	}
	return nil
}

// validate checks the required v1 database indexes and reads the snapshot timestamp.
func validate(destination string, advisories int) (time.Time, error) {
	if advisories == 0 {
		return time.Time{}, fmt.Errorf("invalid vulnerability database: no Go advisory records")
	}
	for _, name := range []string{"index/modules.json", "index/vulns.json"} {
		data, err := os.ReadFile(filepath.Join(destination, filepath.FromSlash(name)))
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid vulnerability database: read %s: %w", name, err)
		}
		var records []json.RawMessage
		if err := json.Unmarshal(data, &records); err != nil {
			return time.Time{}, fmt.Errorf("invalid vulnerability database: parse %s: %w", name, err)
		}
	}
	advisoryPaths, err := filepath.Glob(filepath.Join(destination, "ID", "GO-*.json"))
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid vulnerability database: list advisories: %w", err)
	}
	if len(advisoryPaths) != advisories {
		return time.Time{}, fmt.Errorf("invalid vulnerability database: advisory file count changed during validation")
	}
	for _, advisoryPath := range advisoryPaths {
		data, err := os.ReadFile(advisoryPath)
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid vulnerability database: read %s: %w", filepath.Base(advisoryPath), err)
		}
		var advisory struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(data, &advisory); err != nil {
			return time.Time{}, fmt.Errorf("invalid vulnerability database: parse %s: %w", filepath.Base(advisoryPath), err)
		}
		if advisory.ID == "" || advisory.ID+".json" != filepath.Base(advisoryPath) {
			return time.Time{}, fmt.Errorf("invalid vulnerability database: advisory ID does not match %s", filepath.Base(advisoryPath))
		}
	}
	data, err := os.ReadFile(filepath.Join(destination, "index", "db.json"))
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid vulnerability database: read index/db.json: %w", err)
	}
	var index struct {
		Modified time.Time `json:"modified"`
	}
	if err := json.Unmarshal(data, &index); err != nil {
		return time.Time{}, fmt.Errorf("invalid vulnerability database: parse index/db.json: %w", err)
	}
	if index.Modified.IsZero() {
		return time.Time{}, fmt.Errorf("invalid vulnerability database: index/db.json has no modified timestamp")
	}
	return index.Modified.UTC(), nil
}

// install replaces destination with staging and restores the previous database on failure.
func install(staging, destination string) error {
	backup := staging + ".previous"
	hadPrevious := false
	if _, err := os.Lstat(destination); err == nil {
		if err := os.Rename(destination, backup); err != nil {
			return fmt.Errorf("stage previous vulnerability database: %w", err)
		}
		hadPrevious = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect previous vulnerability database: %w", err)
	}
	if err := os.Rename(staging, destination); err != nil {
		if hadPrevious {
			if restoreErr := os.Rename(backup, destination); restoreErr != nil {
				return fmt.Errorf("install vulnerability database: %w (restore failed: %v)", err, restoreErr)
			}
		}
		return fmt.Errorf("install vulnerability database: %w", err)
	}
	if hadPrevious {
		if err := os.RemoveAll(backup); err != nil {
			return fmt.Errorf("remove previous vulnerability database: %w", err)
		}
	}
	return nil
}
