package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestQueryGroupsAliasesAndFindsFixedVersion verifies advisory grouping and remediation.
func TestQueryGroupsAliasesAndFindsFixedVersion(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var req batchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if got := req.Queries[0].Version; got != "1.2.0" {
			t.Fatalf("OSV Go version=%q", got)
		}
		_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GO-2026-0001"},{"id":"GHSA-aaaa-bbbb-cccc"}]}]}`))
	})
	goRecord := `{"id":"GO-2026-0001","aliases":["CVE-2026-9999","GHSA-aaaa-bbbb-cccc"],"summary":"boom","affected":[{"package":{"ecosystem":"Go","name":"example.com/lib"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]}]}`
	ghsaRecord := `{"id":"GHSA-aaaa-bbbb-cccc","aliases":["CVE-2026-9999","GO-2026-0001"],"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],"database_specific":{"severity":"CRITICAL"},"affected":[{"package":{"ecosystem":"Go","name":"example.com/lib"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]}]}`
	mux.HandleFunc("/v1/vulns/GO-2026-0001", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(goRecord)) })
	mux.HandleFunc("/v1/vulns/GHSA-aaaa-bbbb-cccc", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(ghsaRecord)) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	got, err := (Client{BaseURL: srv.URL, HTTPClient: srv.Client()}).Query(context.Background(), []Target{{Key: "module", Path: "example.com/lib", Version: "v1.2.0"}})
	if err != nil {
		t.Fatal(err)
	}
	vs := got["module"]
	if len(vs) != 1 {
		t.Fatalf("len=%d %#v", len(vs), vs)
	}
	v := vs[0]
	if v.ID != "GO-2026-0001" {
		t.Fatalf("ID=%s", v.ID)
	}
	if v.Fixed != "v1.2.3" {
		t.Fatalf("fixed=%s", v.Fixed)
	}
	if v.CVSS == nil || v.CVSS.Score != 9.8 {
		t.Fatalf("cvss=%+v", v.CVSS)
	}
	if len(v.CVEs) != 1 || v.CVEs[0] != "CVE-2026-9999" {
		t.Fatalf("CVEs=%v", v.CVEs)
	}
}

// TestQueryPagination verifies OSV batch pagination.
func TestQueryPagination(t *testing.T) {
	calls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		calls++
		var req batchRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if calls == 1 {
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GO-1"}],"next_page_token":"next"}]}`))
			return
		}
		if req.Queries[0].PageToken != "next" {
			t.Fatalf("token=%q", req.Queries[0].PageToken)
		}
		_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GO-2"}]}]}`))
	})
	for _, id := range []string{"GO-1", "GO-2"} {
		id := id
		mux.HandleFunc("/v1/vulns/"+id, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"id":"` + id + `","affected":[]}`))
		})
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()
	_, err := (Client{BaseURL: srv.URL, HTTPClient: srv.Client()}).Query(context.Background(), []Target{{Key: "m", Path: "x/y", Version: "v1.0.0"}})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("calls=%d", calls)
	}
}

// TestFixedVersionChoosesCurrentRange verifies disjoint vulnerable-range handling.
func TestFixedVersionChoosesCurrentRange(t *testing.T) {
	var r Record
	jsonText := `{"affected":[{"package":{"ecosystem":"Go","name":"m"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.5.0"},{"introduced":"2.0.0"},{"fixed":"2.1.1"}]}]}]}`
	if err := json.NewDecoder(strings.NewReader(jsonText)).Decode(&r); err != nil {
		t.Fatal(err)
	}
	if got := fixedVersion(r, "m", "v2.0.5"); got != "2.1.1" {
		t.Fatalf("got %q", got)
	}
}

// TestGroupAffectsLoadedPackages verifies package-aware advisory filtering.
func TestGroupAffectsLoadedPackages(t *testing.T) {
	var record Record
	jsonText := `{"id":"GO-1","affected":[{"package":{"ecosystem":"Go","name":"example.com/mod"},"ecosystem_specific":{"imports":[{"path":"example.com/mod/vulnerable","symbols":["Parse"]}]}}]}`
	if err := json.NewDecoder(strings.NewReader(jsonText)).Decode(&record); err != nil {
		t.Fatal(err)
	}
	target := Target{Path: "example.com/mod", PackagesKnown: true, Packages: []string{"example.com/mod/safe"}}
	if groupAffectsPackages(target, []Record{record}) {
		t.Fatal("advisory for an unloaded package should be filtered")
	}
	target.Packages = append(target.Packages, "example.com/mod/vulnerable")
	if !groupAffectsPackages(target, []Record{record}) {
		t.Fatal("advisory for a loaded package should be retained")
	}
	target.Packages = nil
	target.PackagesKnown = false
	if !groupAffectsPackages(target, []Record{record}) {
		t.Fatal("failed package analysis must remain conservative")
	}
}

// TestGroupWithoutImportMetadataRemainsConservative verifies module-level fallback behavior.
func TestGroupWithoutImportMetadataRemainsConservative(t *testing.T) {
	var record Record
	if err := json.NewDecoder(strings.NewReader(`{"id":"GHSA-1","affected":[{"package":{"ecosystem":"Go","name":"example.com/mod"}}]}`)).Decode(&record); err != nil {
		t.Fatal(err)
	}
	if !groupAffectsPackages(Target{Path: "example.com/mod", PackagesKnown: true}, []Record{record}) {
		t.Fatal("module-only advisory should be retained")
	}
}

// TestMergeGroupKeepsAffectedSymbols verifies vulnerable symbol preservation.
func TestMergeGroupKeepsAffectedSymbols(t *testing.T) {
	var record Record
	data := `{"id":"GO-1","affected":[{"package":{"ecosystem":"Go","name":"example.com/mod"},"ecosystem_specific":{"imports":[{"path":"example.com/mod/parser","symbols":["Parse","Decode"]}]}}]}`
	if err := json.NewDecoder(strings.NewReader(data)).Decode(&record); err != nil {
		t.Fatal(err)
	}
	vulnerability := mergeGroup("example.com/mod", "v1.0.0", []Record{record})
	if len(vulnerability.AffectedImports) != 1 || vulnerability.AffectedImports[0].Path != "example.com/mod/parser" || len(vulnerability.AffectedImports[0].Symbols) != 2 {
		t.Fatalf("affected imports=%+v", vulnerability.AffectedImports)
	}
}
