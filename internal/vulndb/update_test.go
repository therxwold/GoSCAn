package vulndb

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestUpdateInstallsAndReplacesSnapshot verifies validated atomic replacement and metadata.
func TestUpdateInstallsAndReplacesSnapshot(t *testing.T) {
	snapshot := testSnapshot(t, map[string]string{
		"index/db.json":        `{"modified":"2026-08-21T20:38:00Z"}`,
		"index/modules.json":   `[]`,
		"index/vulns.json":     `[]`,
		"ID/GO-2026-0001.json": `{"id":"GO-2026-0001"}`,
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(snapshot)
	}))
	defer server.Close()

	parent := t.TempDir()
	destination := filepath.Join(parent, "vulndb")
	if err := os.MkdirAll(destination, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destination, "obsolete"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 24, 1, 2, 3, 0, time.UTC)
	metadata, err := (Updater{URL: server.URL, Now: func() time.Time { return now }}).Update(context.Background(), destination)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Path != destination || metadata.Source != server.URL || metadata.DownloadedAt != now || metadata.Advisories != 1 {
		t.Fatalf("unexpected metadata: %#v", metadata)
	}
	if metadata.Modified.Format(time.RFC3339) != "2026-08-21T20:38:00Z" {
		t.Fatalf("modified=%s", metadata.Modified)
	}
	if !Installed(destination) {
		t.Fatal("installed database was not recognized")
	}
	if _, err := os.Stat(filepath.Join(destination, "obsolete")); !os.IsNotExist(err) {
		t.Fatalf("obsolete database content survived replacement: %v", err)
	}
	if _, err := os.Stat(filepath.Join(destination, ".goscan.json")); err != nil {
		t.Fatalf("metadata file missing: %v", err)
	}
}

// TestUpdateRejectsUnsafeArchiveAndPreservesExisting verifies fail-safe extraction.
func TestUpdateRejectsUnsafeArchiveAndPreservesExisting(t *testing.T) {
	snapshot := testSnapshot(t, map[string]string{"../escape": "unsafe"})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(snapshot)
	}))
	defer server.Close()

	parent := t.TempDir()
	destination := filepath.Join(parent, "vulndb")
	if err := os.MkdirAll(destination, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(destination, "keep")
	if err := os.WriteFile(sentinel, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := (Updater{URL: server.URL}).Update(context.Background(), destination)
	if err == nil || !strings.Contains(err.Error(), "invalid archive path") {
		t.Fatalf("expected unsafe path error, got %v", err)
	}
	data, readErr := os.ReadFile(sentinel)
	if readErr != nil || string(data) != "existing" {
		t.Fatalf("existing database changed: data=%q err=%v", data, readErr)
	}
	if _, err := os.Stat(filepath.Join(parent, "escape")); !os.IsNotExist(err) {
		t.Fatalf("archive escaped its staging directory: %v", err)
	}
}

// TestUpdateRejectsIncompleteDatabase verifies schema checks before installation.
func TestUpdateRejectsIncompleteDatabase(t *testing.T) {
	snapshot := testSnapshot(t, map[string]string{
		"index/db.json":      `{"modified":"2026-08-21T20:38:00Z"}`,
		"index/modules.json": `[]`,
		"index/vulns.json":   `[]`,
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(snapshot)
	}))
	defer server.Close()

	destination := filepath.Join(t.TempDir(), "vulndb")
	_, err := (Updater{URL: server.URL}).Update(context.Background(), destination)
	if err == nil || !strings.Contains(err.Error(), "no Go advisory records") {
		t.Fatalf("expected missing advisory error, got %v", err)
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatalf("invalid database was installed: %v", err)
	}
}

// TestUpdateReportsHTTPFailure verifies unsuccessful downloads are rejected.
func TestUpdateReportsHTTPFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	_, err := (Updater{URL: server.URL}).Update(context.Background(), filepath.Join(t.TempDir(), "vulndb"))
	if err == nil || !strings.Contains(err.Error(), "503 Service Unavailable") {
		t.Fatalf("expected HTTP status error, got %v", err)
	}
}

// TestDatabaseURL verifies supported remote URLs and local path conversion.
func TestDatabaseURL(t *testing.T) {
	if got, err := DatabaseURL("https://example.test/db"); err != nil || got != "https://example.test/db" {
		t.Fatalf("remote URL: got=%q err=%v", got, err)
	}
	local := filepath.Join(t.TempDir(), "vulndb")
	got, err := DatabaseURL(local)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "file://") || !strings.Contains(got, "/vulndb") {
		t.Fatalf("local URL=%q", got)
	}
	if runtime.GOOS == "windows" && !strings.HasPrefix(got, "file:///") {
		t.Fatalf("Windows drive path does not have a canonical file URL: %q", got)
	}
	if runtime.GOOS == "windows" {
		got, err := DatabaseURL(`\\server\share\vulndb`)
		if err != nil {
			t.Fatal(err)
		}
		if got != "file://server/share/vulndb" {
			t.Fatalf("Windows UNC URL=%q", got)
		}
	}
	if got, err := DatabaseURL("file:///C:/vulndb"); err != nil || got != "file:///C:/vulndb" {
		t.Fatalf("existing file URL: got=%q err=%v", got, err)
	}
	if _, err := DatabaseURL("ftp://example.test/db"); err == nil {
		t.Fatal("expected unsupported scheme error")
	}
}

// TestPublicSourceURLRemovesSecrets verifies stored update metadata cannot expose URL credentials.
func TestPublicSourceURLRemovesSecrets(t *testing.T) {
	got := publicSourceURL("https://user:secret@example.test/vulndb.zip?token=secret#fragment")
	if got != "https://example.test/vulndb.zip" {
		t.Fatalf("sanitized URL=%q", got)
	}
}

// testSnapshot constructs an in-memory vulnerability database ZIP for tests.
func testSnapshot(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, contents := range files {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(contents)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
