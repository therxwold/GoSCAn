package model

import "time"

// DependencyKind describes how a selected module is related to the main module.
type DependencyKind string

const (
	// DependencyDirect is explicitly required without // indirect in the main go.mod.
	DependencyDirect DependencyKind = "direct"
	// DependencyIndirect is explicitly required with // indirect in the main go.mod.
	DependencyIndirect DependencyKind = "indirect"
	// DependencyTransitive is selected through another dependency and is not explicitly required.
	DependencyTransitive DependencyKind = "transitive"
	// DependencyMain identifies the module being scanned.
	DependencyMain DependencyKind = "main"
)

// Severity is GoSCAn's normalized vulnerability severity.
type Severity string

const (
	// SeverityUnknown means the source did not provide enough information to classify severity.
	SeverityUnknown Severity = "unknown"
	// SeverityLow represents a low-severity vulnerability.
	SeverityLow Severity = "low"
	// SeverityMedium represents a medium-severity vulnerability.
	SeverityMedium Severity = "medium"
	// SeverityHigh represents a high-severity vulnerability.
	SeverityHigh Severity = "high"
	// SeverityCritical represents a critical-severity vulnerability.
	SeverityCritical Severity = "critical"
)

// Rank returns the ordering value used for severity comparisons.
func (s Severity) Rank() int {
	switch s {
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	default:
		return 0
	}
}

// ModuleRef is a compact module path and version reference used in dependency paths.
type ModuleRef struct {
	Path    string `json:"path"`
	Version string `json:"version,omitempty"`
}

// Module describes one module in the selected Go build list.
type Module struct {
	Path                string         `json:"path"`
	Version             string         `json:"version,omitempty"`
	Kind                DependencyKind `json:"kind"`
	Main                bool           `json:"main,omitempty"`
	Explicit            bool           `json:"explicit,omitempty"`
	IndirectRequirement bool           `json:"indirect_requirement,omitempty"`
	Replace             *ModuleRef     `json:"replace,omitempty"`
	LocalReplacement    bool           `json:"local_replacement,omitempty"`
}

// ScanTarget returns the registry module path and version that represent the code actually selected.
// Versioned replacements use their replacement target; local replacements intentionally have no OSV target.
func (m Module) ScanTarget() (path, version string, ok bool) {
	if m.Main || m.LocalReplacement {
		return "", "", false
	}
	if m.Replace != nil && m.Replace.Path != "" && m.Replace.Version != "" {
		return m.Replace.Path, m.Replace.Version, true
	}
	if m.Path == "" || m.Version == "" {
		return "", "", false
	}
	return m.Path, m.Version, true
}

// CVSS stores normalized Common Vulnerability Scoring System information.
type CVSS struct {
	Version string  `json:"version,omitempty"`
	Vector  string  `json:"vector,omitempty"`
	Score   float64 `json:"score,omitempty"`
	Source  string  `json:"source,omitempty"`
}

// EPSS stores FIRST Exploit Prediction Scoring System probability data.
type EPSS struct {
	Score      float64 `json:"score"`
	Percentile float64 `json:"percentile"`
	Date       string  `json:"date,omitempty"`
}

// AdvisorySource identifies a vulnerability data source used by GoSCAn.
type AdvisorySource string

const (
	// SourceOSV identifies OSV and the Go Vulnerability Database data exposed through OSV.
	SourceOSV AdvisorySource = "osv"
	// SourceGitHub identifies the GitHub Advisory Database.
	SourceGitHub AdvisorySource = "github"
	// SourceNVD identifies the NIST National Vulnerability Database.
	SourceNVD AdvisorySource = "nvd"
)

// Vulnerability is GoSCAn's normalized advisory representation.
type Vulnerability struct {
	ID             string           `json:"id"`
	Aliases        []string         `json:"aliases,omitempty"`
	Summary        string           `json:"summary,omitempty"`
	Details        string           `json:"details,omitempty"`
	CVEs           []string         `json:"cves,omitempty"`
	Fixed          string           `json:"fixed_version,omitempty"`
	CVSS           *CVSS            `json:"cvss,omitempty"`
	EPSS           *EPSS            `json:"epss,omitempty"`
	Severity       Severity         `json:"severity"`
	CWEs           []string         `json:"cwes,omitempty"`
	References     []string         `json:"references,omitempty"`
	Sources        []AdvisorySource `json:"sources,omitempty"`
	KnownExploited bool             `json:"known_exploited,omitempty"`
}

// FixStrategy identifies how GoSCAn recommends changing the module graph.
type FixStrategy string

const (
	// FixDirectUpgrade upgrades an explicitly direct requirement to its first fixed version.
	FixDirectUpgrade FixStrategy = "direct_upgrade"
	// FixTransitivePin adds or raises an indirect requirement so Go MVS selects a safe version.
	FixTransitivePin FixStrategy = "transitive_pin"
)

// GoModChange describes the go.mod requirement produced by a remediation.
type GoModChange struct {
	Module   string `json:"module"`
	Version  string `json:"version"`
	Indirect bool   `json:"indirect"`
	Line     string `json:"line"`
}

// FixRecommendation describes a minimal dependency remediation proposed by GoSCAn.
type FixRecommendation struct {
	Strategy      FixStrategy  `json:"strategy"`
	Module        string       `json:"module"`
	From          string       `json:"from"`
	To            string       `json:"to"`
	Command       string       `json:"command"`
	Reason        string       `json:"reason"`
	GoModChange   *GoModChange `json:"go_mod_change,omitempty"`
	LatestVersion string       `json:"latest_version,omitempty"`
}

// Finding ties one vulnerability to the selected module, graph path, and optional fix.
type Finding struct {
	Module        Module             `json:"module"`
	Vulnerability Vulnerability      `json:"vulnerability"`
	LatestVersion string             `json:"latest_version,omitempty"`
	Paths         [][]ModuleRef      `json:"paths,omitempty"`
	Fix           *FixRecommendation `json:"fix,omitempty"`
	Ignored       bool               `json:"ignored,omitempty"`
	IgnoreRule    string             `json:"ignore_rule,omitempty"`
	IgnoreReason  string             `json:"ignore_reason,omitempty"`
}

// Summary contains dependency and vulnerability counts for a scan.
type Summary struct {
	Modules    int `json:"modules"`
	Direct     int `json:"direct"`
	Indirect   int `json:"indirect"`
	Transitive int `json:"transitive"`
	Skipped    int `json:"skipped"`

	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
	Ignored  int `json:"ignored"`
}

// Report is the complete result of a GoSCAn dependency vulnerability scan.
type Report struct {
	Root            string    `json:"-"`
	ToolVersion     string    `json:"tool_version"`
	Module          string    `json:"module"`
	ScannedAt       time.Time `json:"scanned_at"`
	Summary         Summary   `json:"summary"`
	Findings        []Finding `json:"findings"`
	IgnoredFindings []Finding `json:"ignored_findings,omitempty"`
	Warnings        []string  `json:"warnings,omitempty"`
}
