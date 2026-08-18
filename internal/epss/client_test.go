package epss

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Query().Get("cve"), "CVE-2026-1234") {
			t.Fatalf("query=%s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"data":[{"cve":"CVE-2026-1234","epss":"0.81234","percentile":"0.991","date":"2026-08-21"}]}`))
	}))
	defer srv.Close()
	got, err := (Client{BaseURL: srv.URL, HTTPClient: srv.Client()}).Query(context.Background(), []string{"CVE-2026-1234"})
	if err != nil {
		t.Fatal(err)
	}
	if got["CVE-2026-1234"].Score != .81234 || got["CVE-2026-1234"].Percentile != .991 {
		t.Fatalf("got=%+v", got)
	}
}

func TestChunkCVEsDeduplicates(t *testing.T) {
	got := chunkCVEs([]string{"CVE-1", "CVE-1", "CVE-2"}, 10)
	if len(got) != 2 || len(got[0]) != 1 || len(got[1]) != 1 {
		t.Fatalf("got=%v", got)
	}
}
