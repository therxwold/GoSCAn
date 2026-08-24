package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/therxwold/GoSCAn/internal/model"
)

// currentVersion is the baseline schema emitted by Save.
const currentVersion = 2

// Document is the versioned on-disk representation of a saved finding baseline.
type Document struct {
	Version   int       `json:"version"`
	Generated time.Time `json:"generated"`
	Findings  []Entry   `json:"findings"`
}

// Entry is the stable subset of a finding used for later comparison.
type Entry struct {
	Module  string `json:"module"`
	Version string `json:"version,omitempty"`
	ID      string `json:"id"`
	// Aliases keeps finding identity stable when the preferred advisory ID changes.
	Aliases  []string       `json:"aliases,omitempty"`
	Severity model.Severity `json:"severity,omitempty"`
}

// priorEntry tracks whether one persisted finding matched a current finding.
type priorEntry struct {
	Entry
	matched bool
}

// Save writes the report's active and ignored findings as a versioned JSON baseline.
func Save(path string, report *model.Report) error {
	doc := Document{Version: currentVersion, Generated: time.Now().UTC(), Findings: entries(report)}
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
	if doc.Version != 1 && doc.Version != currentVersion {
		return fmt.Errorf("unsupported baseline version %d", doc.Version)
	}
	previous, index := indexEntries(doc.Findings)
	for i := range report.Findings {
		mark(&report.Findings[i], index, report)
	}
	for i := range report.IgnoredFindings {
		mark(&report.IgnoredFindings[i], index, report)
	}
	// Any baseline entry left unmatched is no longer present in either the
	// active or ignored finding set and is therefore resolved.
	for _, prior := range previous {
		if prior.matched {
			continue
		}
		report.ResolvedFindings = append(report.ResolvedFindings, model.ResolvedFinding{
			Module: model.ModuleRef{Path: prior.Module, Version: prior.Version}, ID: prior.ID, Status: "resolved",
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

// indexEntries creates a lookup for every primary and alias identifier in a baseline.
func indexEntries(entries []Entry) ([]*priorEntry, map[string][]*priorEntry) {
	previous := make([]*priorEntry, 0, len(entries))
	index := map[string][]*priorEntry{}
	for _, entry := range entries {
		prior := &priorEntry{Entry: entry}
		previous = append(previous, prior)
		for _, id := range entryIdentifiers(entry) {
			k := key(entry.Module, id)
			index[k] = append(index[k], prior)
		}
	}
	return previous, index
}

// mark classifies one current finding using primary and alias identifier overlap.
func mark(finding *model.Finding, previous map[string][]*priorEntry, report *model.Report) {
	old := matchingEntry(finding, previous)
	if old != nil {
		// A severity increase is distinct from a merely persistent finding so CI
		// and reviewers can focus on worsened risk.
		if finding.Vulnerability.Severity.Rank() > old.Severity.Rank() {
			finding.BaselineStatus = "regressed"
			report.Summary.BaselineRegressed++
			old.matched = true
			return
		}
		finding.BaselineStatus = "unchanged"
		report.Summary.BaselineUnchanged++
		old.matched = true
		return
	}
	finding.BaselineStatus = "new"
	report.Summary.BaselineNew++
}

// matchingEntry returns an unmatched prior finding sharing a module and identifier.
func matchingEntry(finding *model.Finding, previous map[string][]*priorEntry) *priorEntry {
	for _, id := range findingIdentifiers(*finding) {
		for _, prior := range previous[key(finding.Module.Path, id)] {
			if !prior.matched {
				return prior
			}
		}
	}
	return nil
}

// entries returns a deterministic baseline projection of all report findings.
func entries(report *model.Report) []Entry {
	var out []Entry
	all := append(append([]model.Finding(nil), report.Findings...), report.IgnoredFindings...)
	for _, finding := range all {
		identifiers := findingIdentifiers(finding)
		out = append(out, Entry{
			Module: finding.Module.Path, Version: finding.Module.Version, ID: finding.Vulnerability.ID,
			Aliases: identifiers[1:], Severity: finding.Vulnerability.Severity,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Module != out[j].Module {
			return out[i].Module < out[j].Module
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// findingIdentifiers returns a normalized, deterministic primary-and-alias identifier set.
func findingIdentifiers(finding model.Finding) []string {
	return identifiers(finding.Vulnerability.ID, append(append([]string(nil), finding.Vulnerability.Aliases...), finding.Vulnerability.CVEs...))
}

// entryIdentifiers returns a normalized, deterministic baseline identifier set.
func entryIdentifiers(entry Entry) []string {
	return identifiers(entry.ID, entry.Aliases)
}

// identifiers returns primary first followed by unique sorted aliases.
func identifiers(primary string, aliases []string) []string {
	primary = strings.ToUpper(strings.TrimSpace(primary))
	seen := map[string]bool{}
	if primary != "" {
		seen[primary] = true
	}
	cleaned := make([]string, 0, len(aliases))
	for _, alias := range aliases {
		alias = strings.ToUpper(strings.TrimSpace(alias))
		if alias == "" || seen[alias] {
			continue
		}
		seen[alias] = true
		cleaned = append(cleaned, alias)
	}
	sort.Strings(cleaned)
	return append([]string{primary}, cleaned...)
}

// key builds the collision-resistant identity used to compare baseline entries.
func key(module, id string) string {
	return module + "\x00" + strings.ToUpper(strings.TrimSpace(id))
}
