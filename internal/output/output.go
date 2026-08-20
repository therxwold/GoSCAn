package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/therxwold/GoSCAn/internal/model"
)

// Format identifies a supported GoSCAn report encoding.
type Format string

const (
	// FormatTerminal renders a human-readable terminal report.
	FormatTerminal Format = "terminal"
	// FormatJSON renders the complete report as JSON.
	FormatJSON Format = "json"
	// FormatSARIF renders findings as SARIF 2.1.0.
	FormatSARIF Format = "sarif"
)

// ParseFormat converts a user-facing format name into a Format.
func ParseFormat(v string) (Format, error) {
	switch strings.ToLower(v) {
	case "", "terminal", "text":
		return FormatTerminal, nil
	case "json":
		return FormatJSON, nil
	case "sarif":
		return FormatSARIF, nil
	default:
		return "", fmt.Errorf("invalid format %q (use terminal, json, or sarif)", v)
	}
}

// Write renders report in the requested output format.
func Write(w io.Writer, report *model.Report, format Format) error {
	switch format {
	case FormatJSON:
		return writeJSON(w, report)
	case FormatSARIF:
		return writeSARIF(w, report)
	default:
		return writeTerminal(w, report)
	}
}

func writeJSON(w io.Writer, report *model.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func writeTerminal(w io.Writer, r *model.Report) error {
	fmt.Fprintf(w, "GoSCAn %s\n\n", r.ToolVersion)
	fmt.Fprintf(w, "Module: %s\n", r.Module)
	fmt.Fprintf(w, "Dependencies: %d total (%d direct, %d indirect, %d transitive", r.Summary.Modules, r.Summary.Direct, r.Summary.Indirect, r.Summary.Transitive)
	if r.Summary.Skipped > 0 {
		fmt.Fprintf(w, ", %d skipped", r.Summary.Skipped)
	}
	fmt.Fprintln(w, ")")
	fmt.Fprintf(w, "Vulnerabilities: %d critical, %d high, %d medium, %d low, %d unknown\n", r.Summary.Critical, r.Summary.High, r.Summary.Medium, r.Summary.Low, r.Summary.Unknown)
	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "\nNo known vulnerabilities found.")
		writeWarnings(w, r)
		return nil
	}
	for _, f := range r.Findings {
		v := f.Vulnerability
		fmt.Fprintf(w, "\n%s  %s\n", strings.ToUpper(string(v.Severity)), v.ID)
		if v.Summary != "" {
			fmt.Fprintf(w, "  %s\n", v.Summary)
		}
		fmt.Fprintf(w, "  Module:   %s@%s (%s)\n", f.Module.Path, f.Module.Version, f.Module.Kind)
		if f.Module.Replace != nil {
			fmt.Fprintf(w, "  Replace:  %s@%s\n", f.Module.Replace.Path, f.Module.Replace.Version)
		}
		if v.Fixed != "" {
			fmt.Fprintf(w, "  Fixed:    %s\n", v.Fixed)
		} else {
			fmt.Fprintln(w, "  Fixed:    unavailable")
		}
		if f.LatestVersion != "" {
			fmt.Fprintf(w, "  Latest:   %s\n", f.LatestVersion)
		}
		if v.CVSS != nil {
			source := ""
			if v.CVSS.Source != "" {
				source = ", " + v.CVSS.Source
			}
			fmt.Fprintf(w, "  CVSS:     %.1f (%s%s)\n", v.CVSS.Score, v.CVSS.Version, source)
		} else {
			fmt.Fprintln(w, "  CVSS:     unavailable")
		}
		if v.EPSS != nil {
			fmt.Fprintf(w, "  EPSS:     %.2f%% (percentile %.2f%%)\n", v.EPSS.Score*100, v.EPSS.Percentile*100)
		}
		if len(v.CVEs) > 0 {
			fmt.Fprintf(w, "  CVE:      %s\n", strings.Join(v.CVEs, ", "))
		}
		if len(v.CWEs) > 0 {
			fmt.Fprintf(w, "  CWE:      %s\n", strings.Join(v.CWEs, ", "))
		}
		if len(v.Sources) > 0 {
			sources := make([]string, 0, len(v.Sources))
			for _, source := range v.Sources {
				sources = append(sources, string(source))
			}
			fmt.Fprintf(w, "  Sources:  %s\n", strings.Join(sources, ", "))
		}
		if v.KnownExploited {
			fmt.Fprintln(w, "  CISA KEV: yes")
		}
		if len(f.Paths) > 0 {
			fmt.Fprintln(w, "  Path:")
			for i, ref := range f.Paths[0] {
				prefix := "    "
				if i > 0 {
					prefix += "└── "
				}
				label := ref.Path
				if ref.Version != "" {
					label += "@" + ref.Version
				}
				fmt.Fprintln(w, prefix+label)
			}
		}
		if f.Fix != nil {
			fmt.Fprintf(w, "  Fix:      %s\n", f.Fix.Command)
			if f.Fix.GoModChange != nil {
				fmt.Fprintln(w, "  go.mod recommendation:")
				fmt.Fprintf(w, "    + %s\n", f.Fix.GoModChange.Line)
			}
		}
	}
	writeWarnings(w, r)
	return nil
}

func writeWarnings(w io.Writer, r *model.Report) {
	if len(r.Warnings) == 0 {
		return
	}
	fmt.Fprintln(w, "\nWarnings:")
	for _, warning := range r.Warnings {
		fmt.Fprintf(w, "  - %s\n", warning)
	}
}

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules,omitempty"`
}
type sarifRule struct {
	ID               string       `json:"id"`
	ShortDescription sarifMessage `json:"shortDescription"`
}
type sarifMessage struct {
	Text string `json:"text"`
}
type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    sarifMessage    `json:"message"`
	Locations  []sarifLocation `json:"locations,omitempty"`
	Properties map[string]any  `json:"properties,omitempty"`
}
type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}
type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}
type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

func writeSARIF(w io.Writer, r *model.Report) error {
	rules := map[string]sarifRule{}
	results := make([]sarifResult, 0, len(r.Findings))
	for _, f := range r.Findings {
		v := f.Vulnerability
		rules[v.ID] = sarifRule{ID: v.ID, ShortDescription: sarifMessage{Text: v.Summary}}
		props := map[string]any{"module": f.Module.Path, "version": f.Module.Version, "dependencyKind": f.Module.Kind}
		if v.Fixed != "" {
			props["fixedVersion"] = v.Fixed
		}
		if v.CVSS != nil {
			props["cvss"] = v.CVSS.Score
		}
		if v.EPSS != nil {
			props["epss"] = v.EPSS.Score
		}
		if len(v.CWEs) > 0 {
			props["cwes"] = v.CWEs
		}
		if len(v.Sources) > 0 {
			props["sources"] = v.Sources
		}
		if v.KnownExploited {
			props["knownExploited"] = true
		}
		msg := fmt.Sprintf("%s affects %s@%s", v.ID, f.Module.Path, f.Module.Version)
		if v.Fixed != "" {
			msg += ", fixed in " + v.Fixed
		}
		results = append(results, sarifResult{RuleID: v.ID, Level: sarifLevel(v.Severity), Message: sarifMessage{Text: msg}, Locations: []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{ArtifactLocation: sarifArtifactLocation{URI: "go.mod"}}}}, Properties: props})
	}
	ruleList := make([]sarifRule, 0, len(rules))
	for _, rule := range rules {
		ruleList = append(ruleList, rule)
	}
	log := sarifLog{Version: "2.1.0", Schema: "https://json.schemastore.org/sarif-2.1.0.json", Runs: []sarifRun{{Tool: sarifTool{Driver: sarifDriver{Name: "GoSCAn", Version: r.ToolVersion, Rules: ruleList}}, Results: results}}}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
func sarifLevel(s model.Severity) string {
	switch s {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}
