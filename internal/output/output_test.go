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
		Summary:     model.Summary{Modules: 1, Transitive: 1, High: 1},
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
	for _, want := range []string{"TRANSITIVE", "go.mod recommendation", "// indirect", "EPSS", "CWE-400", "github", "CISA KEV"} {
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
