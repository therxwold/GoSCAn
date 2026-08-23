package baseline

import (
	"path/filepath"
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
