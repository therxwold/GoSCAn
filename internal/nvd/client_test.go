package nvd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/therxwold/GoSCAn/internal/model"
)

// TestQuery verifies NVD request handling and CVE normalization.
func TestQuery(t *testing.T) {
	var apiKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey = r.Header.Get("apiKey")
		if r.URL.Query().Get("cveIds") != "CVE-2026-1000,CVE-2026-2000" {
			t.Fatalf("unexpected cveIds %q", r.URL.Query().Get("cveIds"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
  "vulnerabilities":[{
    "cve":{
      "id":"CVE-2026-1000",
      "descriptions":[{"lang":"en","value":"nvd description"}],
      "metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/test","baseScore":9.8,"baseSeverity":"CRITICAL"}}]},
      "weaknesses":[{"description":[{"lang":"en","value":"CWE-787"}]}],
      "references":[{"url":"https://example.test/nvd-ref"}],
      "cisaExploitAdd":"2026-08-20"
    }
  }]
}`))
	}))
	defer srv.Close()

	got, err := (Client{BaseURL: srv.URL, APIKey: "nvd-secret"}).Query(context.Background(), []string{"CVE-2026-2000", "CVE-2026-1000"})
	if err != nil {
		t.Fatal(err)
	}
	r := got["CVE-2026-1000"]
	if apiKey != "nvd-secret" || r.Description != "nvd description" || !r.KnownExploited {
		t.Fatalf("unexpected result %#v key=%q", r, apiKey)
	}
	if r.CVSS == nil || r.CVSS.Score != 9.8 || r.CVSS.Source != "nvd" || len(r.CWEs) != 1 || r.CWEs[0] != "CWE-787" {
		t.Fatalf("missing metadata %#v", r)
	}
}

// TestNormalizeIncludesCVSSV2 verifies support for legacy CVSS 2.0 metrics.
func TestNormalizeIncludesCVSSV2(t *testing.T) {
	var cve apiCVE
	cve.ID = "CVE-2026-2000"
	var m metric
	m.CVSSData.Version = "2.0"
	m.CVSSData.VectorString = "AV:N/AC:L/Au:N/C:P/I:P/A:P"
	m.CVSSData.BaseScore = 7.5
	m.BaseSeverity = "HIGH"
	cve.Metrics.V2 = []metric{m}

	r := normalize(cve)
	if r.CVSS == nil || r.CVSS.Version != "2.0" || r.CVSS.Score != 7.5 || r.Severity != model.SeverityHigh {
		t.Fatalf("unexpected CVSS v2 metadata: %#v", r)
	}
}
