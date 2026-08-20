package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/therxwold/GoSCAn/internal/model"
)

func sampleReport() *model.Report {
	return &model.Report{
		ToolVersion: "0.1.0",
		Module:      "example.com/app",
		Summary:     model.Summary{Modules: 2, Direct: 1, Transitive: 1, High: 1, Unmaintained: 1, Stale: 1, OutdatedDependencies: 1},
		Go:          &model.GoHealth{Directive: "1.18", Latest: "go1.26.6", RecommendedDirective: "1.26", DirectiveOutdated: true, Unsupported: true},
		Health: []model.DependencyHealth{{
			Module: model.ModuleRef{Path: "github.com/go-martini/martini", Version: "v0.0.0-20170121215854-22fa46961aab"},
			Kind:   model.DependencyTransitive,
			Paths: [][]model.ModuleRef{{
				{Path: "example.com/app"},
				{Path: "example.com/parent", Version: "v1.0.0"},
				{Path: "github.com/go-martini/martini", Version: "v0.0.0-20170121215854-22fa46961aab"},
			}},
			Repository: "go-martini/martini", RepositoryURL: "https://github.com/go-martini/martini",
			Unmaintained: true, Stale: true, MaintenanceNotice: "no longer maintained", LatestVersion: "v1.0.0", Outdated: true,
		}},
		Dependencies: []model.Module{
			{
				Path: "example.com/parent", Version: "v1.0.0", Kind: model.DependencyDirect, GoVersion: "1.22", ManifestAudited: true,
				Requires: []model.ModuleRequirement{{Path: "golang.org/x/net", Version: "v0.18.0", SelectedVersion: "v0.20.0"}},
			},
			{Path: "golang.org/x/net", Version: "v0.20.0", Kind: model.DependencyTransitive, GoVersion: "1.18", ManifestAudited: true},
		},
		Findings: []model.Finding{
			{
				Module: model.Module{Path: "golang.org/x/net", Version: "v0.20.0", Kind: model.DependencyTransitive},
				Vulnerability: model.Vulnerability{
					ID:             "GO-1",
					Severity:       model.SeverityHigh,
					Fixed:          "v0.25.0",
					CVSS:           &model.CVSS{Version: "3.1", Score: 8.1, Source: "nvd"},
					EPSS:           &model.EPSS{Score: .5, Percentile: .9},
					CWEs:           []string{"CWE-400"},
					Sources:        []model.AdvisorySource{model.SourceOSV, model.SourceGitHub, model.SourceNVD},
					KnownExploited: true,
				},
				Fix: &model.FixRecommendation{
					Command:     "go get golang.org/x/net@v0.25.0",
					GoModChange: &model.GoModChange{Line: "require golang.org/x/net v0.25.0 // indirect"},
				},
			},
		},
	}
}

func TestTerminalContainsGoModRecommendation(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, sampleReport(), FormatTerminal); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	for _, want := range []string{"TRANSITIVE", "go.mod recommendation", "// indirect", "EPSS", "CWE-400", "github", "CISA KEV", "Declared by", "example.com/parent@v1.0.0 requires golang.org/x/net@v0.18.0 (selected v0.20.0)", "Go version", "1.18 -> 1.26", "UNMAINTAINED", "no longer maintained", "(transitive)", "example.com/parent@v1.0.0"} {
		if !strings.Contains(strings.ToUpper(s), strings.ToUpper(want)) {
			t.Fatalf("missing %q in %s", want, s)
		}
	}
}

func TestJSON(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, sampleReport(), FormatJSON); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `"tool_version": "0.1.0"`) {
		t.Fatal(b.String())
	}
}

func TestTerminalCanShowDependencyManifests(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, sampleReport(), FormatTerminal, WriteOptions{ShowManifests: true}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Dependency manifests:", "example.com/parent@v1.0.0 (direct, go 1.22)", "requires golang.org/x/net@v0.18.0 -> selected v0.20.0"} {
		if !strings.Contains(b.String(), want) {
			t.Fatalf("missing %q in %s", want, b.String())
		}
	}
}

func TestJSONIncludesDependencyManifests(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, sampleReport(), FormatJSON); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"dependencies"`, `"go_version": "1.22"`, `"selected_version": "v0.20.0"`} {
		if !strings.Contains(b.String(), want) {
			t.Fatalf("missing %s in %s", want, b.String())
		}
	}
}

func TestSARIF(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, sampleReport(), FormatSARIF); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `"version": "2.1.0"`) || !strings.Contains(b.String(), `"ruleId": "GO-1"`) {
		t.Fatal(b.String())
	}
}

func TestIgnoredFindingsAreHiddenUnlessRequested(t *testing.T) {
	r := sampleReport()
	ignored := r.Findings[0]
	ignored.Ignored = true
	ignored.IgnoreRule = "GO-1"
	ignored.IgnoreReason = "accepted false positive"
	r.IgnoredFindings = []model.Finding{ignored}
	r.Summary.Ignored = 1

	var hidden bytes.Buffer
	if err := Write(&hidden, r, FormatTerminal); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(hidden.String(), "accepted false positive") {
		t.Fatal("ignored finding should be hidden by default")
	}
	if !strings.Contains(hidden.String(), "1 ignored") {
		t.Fatal(hidden.String())
	}

	var shown bytes.Buffer
	if err := Write(&shown, r, FormatTerminal, WriteOptions{ShowIgnored: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(shown.String(), "Ignored / false positives") || !strings.Contains(shown.String(), "accepted false positive") {
		t.Fatal(shown.String())
	}
}

func TestJSONKeepsIgnoredFindingsForAudit(t *testing.T) {
	r := sampleReport()
	ignored := r.Findings[0]
	ignored.Ignored = true
	ignored.IgnoreRule = "CVE-1"
	ignored.IgnoreReason = "not affected"
	r.IgnoredFindings = []model.Finding{ignored}

	var b bytes.Buffer
	if err := Write(&b, r, FormatJSON); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"ignored_findings"`, `"ignored": true`, `"ignore_reason": "not affected"`} {
		if !strings.Contains(b.String(), want) {
			t.Fatalf("missing %s in %s", want, b.String())
		}
	}
}

func TestSARIFCanMarkIgnoredFindingAsSuppressed(t *testing.T) {
	r := sampleReport()
	ignored := r.Findings[0]
	ignored.Ignored = true
	ignored.IgnoreRule = "GO-1"
	ignored.IgnoreReason = "accepted false positive"
	r.IgnoredFindings = []model.Finding{ignored}

	var b bytes.Buffer
	if err := Write(&b, r, FormatSARIF, WriteOptions{ShowIgnored: true}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"suppressions"`, `"kind": "external"`, `"status": "accepted"`, `"justification": "accepted false positive"`} {
		if !strings.Contains(b.String(), want) {
			t.Fatalf("missing %s in %s", want, b.String())
		}
	}
}

func TestSARIFIncludesRuntimeAndDependencyHealth(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, sampleReport(), FormatSARIF); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"ruleId": "GOSCAN-GO-UNSUPPORTED"`, `"ruleId": "GOSCAN-DEPENDENCY-UNMAINTAINED"`, `"ruleId": "GOSCAN-DEPENDENCY-OUTDATED"`} {
		if !strings.Contains(b.String(), want) {
			t.Fatalf("missing %s in %s", want, b.String())
		}
	}
}
