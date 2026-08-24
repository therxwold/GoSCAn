package baseline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/therxwold/GoSCAn/internal/model"
)

// TestSaveAndApplyClassifiesFindings verifies baseline persistence and status classification.
func TestSaveAndApplyClassifiesFindings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	old := &model.Report{Findings: []model.Finding{
		{Module: model.Module{Path: "m", Version: "v1"}, Vulnerability: model.Vulnerability{ID: "GO-1", Severity: model.SeverityLow}},
		{Module: model.Module{Path: "gone", Version: "v1"}, Vulnerability: model.Vulnerability{ID: "GO-2"}},
	}}
	if err := Save(path, old); err != nil {
		t.Fatal(err)
	}
	current := &model.Report{Findings: []model.Finding{
		{Module: model.Module{Path: "m", Version: "v1"}, Vulnerability: model.Vulnerability{ID: "GO-1", Severity: model.SeverityHigh}},
		{Module: model.Module{Path: "new", Version: "v1"}, Vulnerability: model.Vulnerability{ID: "GO-3"}},
	}}
	if err := Apply(path, current); err != nil {
		t.Fatal(err)
	}
	if current.Findings[0].BaselineStatus != "regressed" || current.Findings[1].BaselineStatus != "new" || len(current.ResolvedFindings) != 1 || current.ResolvedFindings[0].ID != "GO-2" || current.Summary.BaselineRegressed != 1 {
		t.Fatalf("report=%+v", current)
	}
}

// TestSaveWritesAliasAwareVersion verifies the current baseline schema persists aliases.
func TestSaveWritesAliasAwareVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	report := &model.Report{Findings: []model.Finding{{
		Module:        model.Module{Path: "m", Version: "v1"},
		Vulnerability: model.Vulnerability{ID: "GO-1", Aliases: []string{"CVE-1"}, CVEs: []string{"CVE-1"}},
	}}}
	if err := Save(path, report); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `"version": 2`) || !strings.Contains(text, `"aliases"`) || strings.Count(text, "CVE-1") != 1 {
		t.Fatalf("baseline=%s", text)
	}
}

// TestApplyMatchesChangedCanonicalID verifies alias overlap prevents false new/resolved findings.
func TestApplyMatchesChangedCanonicalID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	old := &model.Report{Findings: []model.Finding{{
		Module:        model.Module{Path: "m", Version: "v1"},
		Vulnerability: model.Vulnerability{ID: "CVE-1", Aliases: []string{"GO-1"}, Severity: model.SeverityHigh},
	}}}
	if err := Save(path, old); err != nil {
		t.Fatal(err)
	}
	current := &model.Report{Findings: []model.Finding{{
		Module:        model.Module{Path: "m", Version: "v1"},
		Vulnerability: model.Vulnerability{ID: "GO-1", Aliases: []string{"CVE-1"}, Severity: model.SeverityHigh},
	}}}
	if err := Apply(path, current); err != nil {
		t.Fatal(err)
	}
	if current.Findings[0].BaselineStatus != "unchanged" || len(current.ResolvedFindings) != 0 || current.Summary.BaselineNew != 0 {
		t.Fatalf("report=%+v", current)
	}
}

// TestApplyReadsVersionOneWithEmptySeverity verifies legacy unknown severity handling.
func TestApplyReadsVersionOneWithEmptySeverity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	data := []byte(`{"version":1,"findings":[{"module":"m","id":"GO-1"}]}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	current := &model.Report{Findings: []model.Finding{{
		Module: model.Module{Path: "m"}, Vulnerability: model.Vulnerability{ID: "GO-1", Severity: model.SeverityUnknown},
	}}}
	if err := Apply(path, current); err != nil {
		t.Fatal(err)
	}
	if current.Findings[0].BaselineStatus != "unchanged" {
		t.Fatalf("finding=%+v", current.Findings[0])
	}
}
