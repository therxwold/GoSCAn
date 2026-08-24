package app

import (
	"archive/zip"
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRunDBUpdate verifies CLI dispatch, installation, and summary output.
func TestRunDBUpdate(t *testing.T) {
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	files := map[string]string{
		"index/db.json":        `{"modified":"2026-08-21T20:38:00Z"}`,
		"index/modules.json":   `[]`,
		"index/vulns.json":     `[]`,
		"ID/GO-2026-0001.json": `{"id":"GO-2026-0001"}`,
	}
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive.Bytes())
	}))
	defer server.Close()

	destination := filepath.Join(t.TempDir(), "vulndb")
	var stdout, stderr bytes.Buffer
	code := run([]string{"db", "update", "--url", server.URL, "--path", destination}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Advisories: 1") {
		t.Fatalf("stdout=%q", stdout.String())
	}
	if _, err := os.Stat(filepath.Join(destination, "index", "db.json")); err != nil {
		t.Fatalf("database was not installed: %v", err)
	}
}

// TestRunDBRejectsUnknownCommand verifies database subcommand errors are explicit.
func TestRunDBRejectsUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"db", "remove"}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(stderr.String(), `unknown command "remove"`) {
		t.Fatalf("stderr=%q", stderr.String())
	}
}
