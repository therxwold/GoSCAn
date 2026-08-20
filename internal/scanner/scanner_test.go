package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/therxwold/GoSCAn/internal/dependency"
	"github.com/therxwold/GoSCAn/internal/githubadvisory"
	"github.com/therxwold/GoSCAn/internal/model"
	"github.com/therxwold/GoSCAn/internal/nvd"
	"github.com/therxwold/GoSCAn/internal/osv"
)

type fakeDeps struct{ result *dependency.Result }

func (f fakeDeps) Load(context.Context, string) (*dependency.Result, error) { return f.result, nil }

type fakeVulns struct{}

func (fakeVulns) Query(_ context.Context, targets []osv.Target) (map[string][]model.Vulnerability, error) {
	out := map[string][]model.Vulnerability{}
	for _, t := range targets {
		if t.Path == "example.com/deep" {
			out[t.Key] = []model.Vulnerability{{ID: "GO-2026-1", Fixed: "v1.2.3", Severity: model.SeverityHigh, CVEs: []string{"CVE-2026-1"}}}
		}
	}
	return out, nil
}

type fakeEPSS struct{}

func (fakeEPSS) Query(context.Context, []string) (map[string]model.EPSS, error) {
	return map[string]model.EPSS{"CVE-2026-1": {Score: .7, Percentile: .98}}, nil
}

type fakeLatest struct{}

func (fakeLatest) Latest(context.Context, string, string) (string, error) { return "v1.9.0", nil }

func TestScanIncludesTransitiveAndRecommendsGoModPin(t *testing.T) {
	g := dependency.NewGraph(map[string]string{"example.com/app": "", "example.com/direct": "v1.0.0", "example.com/deep": "v1.2.0"})
	g.AddRoot("example.com/app")
	// ParseGraph is easiest way to add edges.
	g = dependency.ParseGraph([]byte("example.com/app example.com/direct@v1.0.0\nexample.com/direct@v1.0.0 example.com/deep@v1.2.0\n"), map[string]string{"example.com/app": "", "example.com/direct": "v1.0.0", "example.com/deep": "v1.2.0"})
	g.AddRoot("example.com/app")
	s := &Scanner{Dependencies: fakeDeps{&dependency.Result{Root: "/x", MainModule: "example.com/app", Modules: []model.Module{
		{Path: "example.com/app", Main: true, Kind: model.DependencyMain},
		{Path: "example.com/direct", Version: "v1.0.0", Kind: model.DependencyDirect},
		{Path: "example.com/deep", Version: "v1.2.0", Kind: model.DependencyTransitive},
	}, Graph: g}}, Vulnerabilities: fakeVulns{}, EPSS: fakeEPSS{}, Versions: fakeLatest{}, Now: func() time.Time { return time.Unix(0, 0) }}
	r, err := s.Scan(context.Background(), ".", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Summary.Modules != 2 || r.Summary.Transitive != 1 {
		t.Fatalf("summary=%+v", r.Summary)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("findings=%d", len(r.Findings))
	}
	f := r.Findings[0]
	if f.Module.Kind != model.DependencyTransitive {
		t.Fatalf("kind=%s", f.Module.Kind)
	}
	if f.Fix == nil || f.Fix.Strategy != model.FixTransitivePin || f.Fix.GoModChange == nil {
		t.Fatalf("fix=%+v", f.Fix)
	}
	if f.Vulnerability.EPSS == nil || f.Vulnerability.EPSS.Score != .7 {
		t.Fatalf("epss=%+v", f.Vulnerability.EPSS)
	}
	if len(f.Paths) != 1 || len(f.Paths[0]) != 3 {
		t.Fatalf("paths=%v", f.Paths)
	}
}

func TestExceeds(t *testing.T) {
	r := &model.Report{Findings: []model.Finding{{Vulnerability: model.Vulnerability{Severity: model.SeverityHigh, EPSS: &model.EPSS{Score: .2}}}}}
	if !Exceeds(r, model.SeverityHigh, -1) {
		t.Fatal("severity")
	}
	if !Exceeds(r, model.SeverityUnknown, .1) {
		t.Fatal("epss")
	}
	if Exceeds(r, model.SeverityCritical, .9) {
		t.Fatal("unexpected")
	}
}

type fakeGitHub struct{}

func (fakeGitHub) Query(context.Context, []string) (map[string]githubadvisory.Record, error) {
	return map[string]githubadvisory.Record{
		"CVE-2026-1": {
			GHSAID:           "GHSA-test-1234-5678",
			CVEID:            "CVE-2026-1",
			Severity:         model.SeverityHigh,
			CVSS:             &model.CVSS{Version: "3.1", Score: 8.4, Source: "github"},
			CWEs:             []string{"CWE-400"},
			References:       []string{"https://github.test/advisory"},
			FirstPatchedByGo: map[string]string{"example.com/deep": "v1.2.3"},
		},
	}, nil
}

type fakeNVD struct{}

func (fakeNVD) Query(context.Context, []string) (map[string]nvd.Record, error) {
	return map[string]nvd.Record{
		"CVE-2026-1": {
			ID:             "CVE-2026-1",
			Severity:       model.SeverityCritical,
			CVSS:           &model.CVSS{Version: "3.1", Score: 9.8, Source: "nvd"},
			CWEs:           []string{"CWE-787"},
			References:     []string{"https://nvd.test/cve"},
			KnownExploited: true,
		},
	}, nil
}

func TestScanEnrichesGitHubAndNVD(t *testing.T) {
	g := dependency.ParseGraph([]byte("example.com/app example.com/deep@v1.2.0\n"), map[string]string{"example.com/app": "", "example.com/deep": "v1.2.0"})
	g.AddRoot("example.com/app")
	s := &Scanner{
		Dependencies: fakeDeps{&dependency.Result{Root: "/x", MainModule: "example.com/app", Modules: []model.Module{
			{Path: "example.com/app", Main: true, Kind: model.DependencyMain},
			{Path: "example.com/deep", Version: "v1.2.0", Kind: model.DependencyDirect},
		}, Graph: g}},
		Vulnerabilities: fakeVulns{}, GitHub: fakeGitHub{}, NVD: fakeNVD{}, EPSS: fakeEPSS{}, Versions: fakeLatest{},
	}
	r, err := s.Scan(context.Background(), ".", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("findings=%d", len(r.Findings))
	}
	v := r.Findings[0].Vulnerability
	if v.CVSS == nil || v.CVSS.Score != 9.8 || v.CVSS.Source != "nvd" || v.Severity != model.SeverityCritical {
		t.Fatalf("unexpected risk %#v", v)
	}
	if !v.KnownExploited || len(v.CWEs) != 2 || len(v.Sources) != 2 {
		t.Fatalf("unexpected enrichment %#v", v)
	}
	if r.Findings[0].Fix == nil || r.Findings[0].Fix.To != "v1.2.3" {
		t.Fatalf("unexpected fix %#v", r.Findings[0].Fix)
	}
}
