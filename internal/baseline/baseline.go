package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/therxwold/GoSCAn/internal/model"
)

// Document is the versioned on-disk representation of a saved finding baseline.
type Document struct {
	Version   int       `json:"version"`
	Generated time.Time `json:"generated"`
	Findings  []Entry   `json:"findings"`
}

// Entry is the stable subset of a finding used for later comparison.
type Entry struct {
	Module   string         `json:"module"`
	Version  string         `json:"version,omitempty"`
	ID       string         `json:"id"`
	Severity model.Severity `json:"severity,omitempty"`
}

// Save writes the report's active and ignored findings as a versioned JSON baseline.
func Save(path string, report *model.Report) error {
	doc := Document{Version: 1, Generated: time.Now().UTC(), Findings: entries(report)}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write baseline: %w", err)
	}
	return nil
}

// Apply compares report findings with a saved baseline and annotates their status.
func Apply(path string, report *model.Report) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read baseline: %w", err)
	}
	var doc Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("decode baseline: %w", err)
	}
	if doc.Version != 1 {
		return fmt.Errorf("unsupported baseline version %d", doc.Version)
	}
	previous := map[string]Entry{}
	for _, entry := range doc.Findings {
		previous[key(entry.Module, entry.ID)] = entry
	}
	for i := range report.Findings {
		mark(&report.Findings[i], previous, report)
	}
	for i := range report.IgnoredFindings {
		mark(&report.IgnoredFindings[i], previous, report)
	}
	// Any baseline entry left unmatched is no longer present in either the
	// active or ignored finding set and is therefore resolved.
	for _, entry := range previous {
		report.ResolvedFindings = append(report.ResolvedFindings, model.ResolvedFinding{
			Module: model.ModuleRef{Path: entry.Module, Version: entry.Version}, ID: entry.ID, Status: "resolved",
		})
		report.Summary.BaselineResolved++
	}
	sort.Slice(report.ResolvedFindings, func(i, j int) bool {
		if report.ResolvedFindings[i].Module.Path != report.ResolvedFindings[j].Module.Path {
			return report.ResolvedFindings[i].Module.Path < report.ResolvedFindings[j].Module.Path
		}
		return report.ResolvedFindings[i].ID < report.ResolvedFindings[j].ID
	})
	return nil
}

// mark classifies one current finding and removes any matching prior entry.
func mark(finding *model.Finding, previous map[string]Entry, report *model.Report) {
	k := key(finding.Module.Path, finding.Vulnerability.ID)
	if old, ok := previous[k]; ok {
		// A severity increase is distinct from a merely persistent finding so CI
		// and reviewers can focus on worsened risk.
		if finding.Vulnerability.Severity.Rank() > old.Severity.Rank() {
			finding.BaselineStatus = "regressed"
			report.Summary.BaselineRegressed++
			delete(previous, k)
			return
		}
		finding.BaselineStatus = "unchanged"
		report.Summary.BaselineUnchanged++
		delete(previous, k)
		return
	}
	finding.BaselineStatus = "new"
	report.Summary.BaselineNew++
}

// entries returns a deterministic baseline projection of all report findings.
func entries(report *model.Report) []Entry {
	var out []Entry
	all := append(append([]model.Finding(nil), report.Findings...), report.IgnoredFindings...)
	for _, finding := range all {
		out = append(out, Entry{Module: finding.Module.Path, Version: finding.Module.Version, ID: finding.Vulnerability.ID, Severity: finding.Vulnerability.Severity})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Module != out[j].Module {
			return out[i].Module < out[j].Module
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// key builds the collision-resistant identity used to compare baseline entries.
func key(module, id string) string {
	return module + "\x00" + id
}
