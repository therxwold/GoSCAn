package scanner

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/therxwold/GoSCAn/internal/dependency"
	"github.com/therxwold/GoSCAn/internal/githubadvisory"
	"github.com/therxwold/GoSCAn/internal/githubrepo"
	"github.com/therxwold/GoSCAn/internal/gorelease"
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
		{Path: "example.com/direct", Version: "v1.0.0", Kind: model.DependencyDirect, GoVersion: "1.22", ManifestAudited: true, Requires: []model.ModuleRequirement{{Path: "example.com/deep", Version: "v1.1.0", SelectedVersion: "v1.2.0"}}},
		{Path: "example.com/deep", Version: "v1.2.0", Kind: model.DependencyTransitive, ManifestAudited: true},
	}, Graph: g}}, Vulnerabilities: fakeVulns{}, EPSS: fakeEPSS{}, Versions: fakeLatest{}, Now: func() time.Time { return time.Unix(0, 0) }}
	r, err := s.Scan(context.Background(), ".", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Summary.Modules != 2 || r.Summary.Transitive != 1 || r.Summary.Manifests != 2 || r.Summary.ManifestErrors != 0 {
		t.Fatalf("summary=%+v", r.Summary)
	}
	if len(r.Dependencies) != 2 {
		t.Fatalf("dependency manifests=%+v", r.Dependencies)
	}
	var direct *model.Module
	for i := range r.Dependencies {
		if r.Dependencies[i].Path == "example.com/direct" {
			direct = &r.Dependencies[i]
		}
	}
	if direct == nil || len(direct.Requires) != 1 || direct.Requires[0].Path != "example.com/deep" {
		t.Fatalf("dependency manifests=%+v", r.Dependencies)
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

type failingGitHub struct{}

func (failingGitHub) Query(context.Context, []string) (map[string]githubadvisory.Record, error) {
	return nil, errors.New("github is having a day")
}

type failingNVD struct{}

func (failingNVD) Query(context.Context, []string) (map[string]nvd.Record, error) {
	return nil, errors.New("nvd is also having a day")
}

func TestScanKeepsOSVFindingWhenEnrichmentFails(t *testing.T) {
	g := dependency.ParseGraph([]byte("example.com/app example.com/deep@v1.2.0\n"), map[string]string{"example.com/app": "", "example.com/deep": "v1.2.0"})
	g.AddRoot("example.com/app")
	s := &Scanner{
		Dependencies: fakeDeps{&dependency.Result{Root: "/x", MainModule: "example.com/app", Modules: []model.Module{
			{Path: "example.com/app", Main: true, Kind: model.DependencyMain},
			{Path: "example.com/deep", Version: "v1.2.0", Kind: model.DependencyDirect},
		}, Graph: g}},
		Vulnerabilities: fakeVulns{}, GitHub: failingGitHub{}, NVD: failingNVD{}, Versions: fakeLatest{},
	}
	r, err := s.Scan(context.Background(), ".", Options{NoEPSS: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("OSV finding disappeared: %#v", r)
	}
	if len(r.Warnings) != 2 {
		t.Fatalf("expected enrichment warnings, got %v", r.Warnings)
	}
}

func TestScanIgnoresFalsePositiveByAlias(t *testing.T) {
	g := dependency.ParseGraph([]byte("example.com/app example.com/deep@v1.2.0\n"), map[string]string{"example.com/app": "", "example.com/deep": "v1.2.0"})
	g.AddRoot("example.com/app")
	s := &Scanner{
		Dependencies: fakeDeps{&dependency.Result{Root: "/x", MainModule: "example.com/app", Modules: []model.Module{
			{Path: "example.com/app", Main: true, Kind: model.DependencyMain},
			{Path: "example.com/deep", Version: "v1.2.0", Kind: model.DependencyDirect},
		}, Graph: g}},
		Vulnerabilities: fakeVulns{}, Versions: fakeLatest{},
	}
	r, err := s.Scan(context.Background(), ".", Options{NoGitHub: true, NoNVD: true, NoEPSS: true, IgnoreRules: map[string]string{
		"CVE-2026-1": "false positive in this application",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 || len(r.IgnoredFindings) != 1 || r.Summary.Ignored != 1 {
		t.Fatalf("unexpected ignored findings: %#v", r)
	}
	ignored := r.IgnoredFindings[0]
	if !ignored.Ignored || ignored.IgnoreRule != "CVE-2026-1" || ignored.IgnoreReason != "false positive in this application" {
		t.Fatalf("unexpected ignore metadata: %#v", ignored)
	}
	if ignored.Fix != nil {
		t.Fatalf("ignored finding should not have a fix: %#v", ignored.Fix)
	}
	if Exceeds(r, model.SeverityLow, 0) {
		t.Fatal("ignored finding must not fail CI policy")
	}
}

func TestModuleScopedIgnoreDoesNotSuppressAnotherModule(t *testing.T) {
	finding := model.Finding{
		Module:        model.Module{Path: "example.com/deep", Version: "v1.2.0"},
		Vulnerability: model.Vulnerability{ID: "GO-2026-1", Aliases: []string{"GHSA-test-1234-5678"}, CVEs: []string{"CVE-2026-1"}},
	}
	if _, _, ok := matchingIgnoreRule(finding, map[string]string{"example.com/other@CVE-2026-1": "other module only"}); ok {
		t.Fatal("module-scoped rule matched the wrong module")
	}
	rule, reason, ok := matchingIgnoreRule(finding, map[string]string{"example.com/deep@GHSA-test-1234-5678": "accepted false positive"})
	if !ok || rule != "example.com/deep@GHSA-test-1234-5678" || reason != "accepted false positive" {
		t.Fatalf("unexpected scoped match: rule=%q reason=%q ok=%v", rule, reason, ok)
	}
}

type failingEPSS struct{}

func (failingEPSS) Query(context.Context, []string) (map[string]model.EPSS, error) {
	return nil, errors.New("epss is having a day")
}

func TestStrictEnrichmentFailsClosed(t *testing.T) {
	g := dependency.ParseGraph([]byte("example.com/app example.com/deep@v1.2.0\n"), map[string]string{"example.com/app": "", "example.com/deep": "v1.2.0"})
	g.AddRoot("example.com/app")
	s := &Scanner{
		Dependencies: fakeDeps{&dependency.Result{Root: "/x", MainModule: "example.com/app", Modules: []model.Module{
			{Path: "example.com/app", Main: true, Kind: model.DependencyMain},
			{Path: "example.com/deep", Version: "v1.2.0", Kind: model.DependencyDirect},
		}, Graph: g}},
		Vulnerabilities: fakeVulns{}, GitHub: failingGitHub{}, Versions: fakeLatest{},
	}
	if _, err := s.Scan(context.Background(), ".", Options{StrictEnrichment: true, NoNVD: true, NoEPSS: true}); err == nil || !strings.Contains(err.Error(), "GitHub advisory enrichment failed") {
		t.Fatalf("expected strict enrichment error, got %v", err)
	}
}

func TestRequiredEPSSFailsClosed(t *testing.T) {
	g := dependency.ParseGraph([]byte("example.com/app example.com/deep@v1.2.0\n"), map[string]string{"example.com/app": "", "example.com/deep": "v1.2.0"})
	g.AddRoot("example.com/app")
	s := &Scanner{
		Dependencies: fakeDeps{&dependency.Result{Root: "/x", MainModule: "example.com/app", Modules: []model.Module{
			{Path: "example.com/app", Main: true, Kind: model.DependencyMain},
			{Path: "example.com/deep", Version: "v1.2.0", Kind: model.DependencyDirect},
		}, Graph: g}},
		Vulnerabilities: fakeVulns{}, EPSS: failingEPSS{}, Versions: fakeLatest{},
	}
	if _, err := s.Scan(context.Background(), ".", Options{NoGitHub: true, NoNVD: true, RequireEPSS: true}); err == nil || !strings.Contains(err.Error(), "EPSS enrichment failed") {
		t.Fatalf("expected required EPSS error, got %v", err)
	}
}

type fakeGoRelease struct{}

func (fakeGoRelease) Latest(context.Context) (gorelease.Release, error) {
	return gorelease.Release{Version: "go1.26.6", LanguageVersion: "1.26"}, nil
}

type fakeRepositories struct{}

func (fakeRepositories) Query(context.Context, []string, time.Time) (map[string]githubrepo.Record, error) {
	return map[string]githubrepo.Record{
		"go-martini/martini": {
			Repository:           "go-martini/martini",
			URL:                  "https://github.com/go-martini/martini",
			PushedAt:             time.Date(2016, 11, 1, 0, 0, 0, 0, time.UTC),
			ExplicitUnmaintained: true,
			MaintenanceNotice:    "no longer maintained",
		},
	}, nil
}

type healthLatest struct{}

func (healthLatest) Latest(_ context.Context, _ string, module string) (string, error) {
	if module == "github.com/go-martini/martini" {
		return "v0.0.0-20170121215854-22fa46961aab", nil
	}
	return "", nil
}

func TestScanFlagsGo118AndUnmaintainedMartiniFixture(t *testing.T) {
	g := dependency.ParseGraph([]byte("filemanager github.com/go-martini/martini@v0.0.0-20170121215854-22fa46961aab\n"), map[string]string{
		"filemanager": "", "github.com/go-martini/martini": "v0.0.0-20170121215854-22fa46961aab",
	})
	g.AddRoot("filemanager")
	s := &Scanner{
		Dependencies: fakeDeps{&dependency.Result{Root: "/x", MainModule: "filemanager", GoDirective: "1.18", Modules: []model.Module{
			{Path: "filemanager", Main: true, Kind: model.DependencyMain},
			{Path: "github.com/go-martini/martini", Version: "v0.0.0-20170121215854-22fa46961aab", Kind: model.DependencyDirect, ManifestAudited: true},
		}, Graph: g}},
		Vulnerabilities: fakeVulns{}, GoReleases: fakeGoRelease{}, Repositories: fakeRepositories{}, Versions: healthLatest{},
		Now: func() time.Time { return time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC) },
	}
	r, err := s.Scan(context.Background(), ".", Options{NoGitHub: true, NoNVD: true, NoEPSS: true, StaleAfter: 730 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if r.Go == nil || !r.Go.DirectiveOutdated || !r.Go.Unsupported || r.Go.RecommendedDirective != "1.26" {
		t.Fatalf("go health=%+v", r.Go)
	}
	if r.Summary.Unmaintained != 1 || r.Summary.Stale != 1 || len(r.Health) != 1 {
		t.Fatalf("health summary=%+v findings=%+v", r.Summary, r.Health)
	}
	if !r.Health[0].Unmaintained || r.Health[0].MaintenanceNotice != "no longer maintained" {
		t.Fatalf("dependency health=%+v", r.Health[0])
	}
	if !HealthExceeds(r, true, true) {
		t.Fatal("health policies should fail")
	}
}

type transitiveHealthLatest struct{}

func (transitiveHealthLatest) Latest(_ context.Context, _ string, module string) (string, error) {
	switch module {
	case "github.com/acme/parent":
		return "v1.0.0", nil
	case "github.com/acme/transitive":
		return "v1.2.0", nil
	default:
		return "", nil
	}
}

type transitiveHealthRepositories struct{}

func (transitiveHealthRepositories) Query(_ context.Context, modules []string, _ time.Time) (map[string]githubrepo.Record, error) {
	found := false
	for _, module := range modules {
		if module == "github.com/acme/transitive" {
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("transitive module was not included in maintenance scan")
	}
	return map[string]githubrepo.Record{
		"acme/transitive": {
			Repository:           "acme/transitive",
			URL:                  "https://github.com/acme/transitive",
			PushedAt:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
			ExplicitUnmaintained: true,
			MaintenanceNotice:    "no longer maintained",
		},
	}, nil
}

func TestScanChecksSelectedTransitiveDependencyHealth(t *testing.T) {
	selected := map[string]string{
		"example.com/app":            "",
		"github.com/acme/parent":     "v1.0.0",
		"github.com/acme/transitive": "v1.2.0",
	}
	g := dependency.ParseGraph([]byte(
		"example.com/app github.com/acme/parent@v1.0.0\n"+
			"github.com/acme/parent@v1.0.0 github.com/acme/transitive@v1.2.0\n",
	), selected)
	g.AddRoot("example.com/app")
	s := &Scanner{
		Dependencies: fakeDeps{&dependency.Result{Root: "/x", MainModule: "example.com/app", Modules: []model.Module{
			{Path: "example.com/app", Main: true, Kind: model.DependencyMain},
			{Path: "github.com/acme/parent", Version: "v1.0.0", Kind: model.DependencyDirect, ManifestAudited: true},
			{Path: "github.com/acme/transitive", Version: "v1.2.0", Kind: model.DependencyTransitive, ManifestAudited: true},
		}, Graph: g}},
		Vulnerabilities: fakeVulns{},
		Versions:        transitiveHealthLatest{},
		Repositories:    transitiveHealthRepositories{},
		Now:             func() time.Time { return time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC) },
	}
	r, err := s.Scan(context.Background(), ".", Options{NoGoVersion: true, NoGitHub: true, NoNVD: true, NoEPSS: true})
	if err != nil {
		t.Fatal(err)
	}
	if r.Summary.Transitive != 1 || r.Summary.Unmaintained != 1 {
		t.Fatalf("summary=%+v", r.Summary)
	}
	if len(r.Health) != 1 {
		t.Fatalf("health=%+v", r.Health)
	}
	h := r.Health[0]
	if h.Module.Path != "github.com/acme/transitive" || h.Kind != model.DependencyTransitive || !h.Unmaintained {
		t.Fatalf("transitive health=%+v", h)
	}
	if len(h.Paths) != 1 || len(h.Paths[0]) != 3 {
		t.Fatalf("paths=%+v", h.Paths)
	}
	if h.Paths[0][1].Path != "github.com/acme/parent" || h.Paths[0][2].Path != "github.com/acme/transitive" {
		t.Fatalf("unexpected path=%+v", h.Paths[0])
	}
}

func TestToolchainUpgradeRecommendation(t *testing.T) {
	s := &Scanner{GoReleases: fakeGoRelease{}}
	report := &model.Report{}
	deps := &dependency.Result{GoDirective: "1.26", Toolchain: "go1.26.1"}
	if err := s.checkGoVersion(context.Background(), deps, report, Options{}); err != nil {
		t.Fatal(err)
	}
	if report.Go == nil || report.Go.DirectiveOutdated || !report.Go.ToolchainOutdated || report.Go.RecommendedToolchain != "go1.26.6" {
		t.Fatalf("go health=%+v", report.Go)
	}
}
