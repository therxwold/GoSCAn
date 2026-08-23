package githubadvisory

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestQueryByGHSA verifies direct advisory lookup and normalization.
func TestQueryByGHSA(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		if r.URL.Path != "/advisories/GHSA-test-1234-5678" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
  "ghsa_id":"GHSA-test-1234-5678",
  "cve_id":"CVE-2026-1000",
  "type":"reviewed",
  "summary":"github summary",
  "description":"github details",
  "severity":"high",
  "references":["https://example.test/ref"],
  "cvss_severities":{"cvss_v3":{"vector_string":"CVSS:3.1/test","score":8.1}},
  "cwes":[{"cwe_id":"CWE-400"}],
  "vulnerabilities":[{"package":{"ecosystem":"go","name":"example.com/mod"},"first_patched_version":"1.2.3"}]
}`))
	}))
	defer srv.Close()

	got, err := (Client{BaseURL: srv.URL, Token: "secret"}).Query(context.Background(), []string{"GHSA-test-1234-5678"})
	if err != nil {
		t.Fatal(err)
	}
	r := got["GHSA-test-1234-5678"]
	if auth != "Bearer secret" || r.CVEID != "CVE-2026-1000" || r.FirstPatchedByGo["example.com/mod"] != "v1.2.3" {
		t.Fatalf("unexpected record %#v auth=%q", r, auth)
	}
	if r.CVSS == nil || r.CVSS.Score != 8.1 || len(r.CWEs) != 1 || r.CWEs[0] != "CWE-400" {
		t.Fatalf("missing metadata %#v", r)
	}
}

// TestQueryByCVEUsesReviewedGoFilter verifies filtered CVE advisory searches.
func TestQueryByCVEUsesReviewedGoFilter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("cve_id") != "CVE-2026-2000" || q.Get("ecosystem") != "go" || q.Get("type") != "reviewed" {
			t.Fatalf("unexpected query %v", q)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"ghsa_id":"GHSA-a-b-c","cve_id":"CVE-2026-2000","type":"reviewed","severity":"medium"}]`))
	}))
	defer srv.Close()
	got, err := (Client{BaseURL: srv.URL}).Query(context.Background(), []string{"CVE-2026-2000"})
	if err != nil {
		t.Fatal(err)
	}
	if got["CVE-2026-2000"].GHSAID != "GHSA-a-b-c" {
		t.Fatalf("unexpected result %#v", got)
	}
}
