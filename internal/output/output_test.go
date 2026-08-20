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
