package gorelease

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLatestStableRelease(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dl/" || r.URL.Query().Get("mode") != "json" {
			t.Fatalf("unexpected request %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`[{"version":"go1.25.8","stable":true},{"version":"go1.27rc3","stable":false},{"version":"go1.26.6","stable":true}]`))
	}))
	defer srv.Close()

	release, err := (Client{BaseURL: srv.URL}).Latest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if release.Version != "go1.26.6" || release.LanguageVersion != "1.26" {
		t.Fatalf("release=%+v", release)
	}
}

func TestSupportedReleaseLines(t *testing.T) {
	if !Supported("1.26", "1.26") || !Supported("1.25", "1.26") {
		t.Fatal("latest two release lines should be supported")
	}
	if Supported("1.24", "1.26") || Supported("1.18", "1.26") {
		t.Fatal("old release line unexpectedly supported")
	}
}
