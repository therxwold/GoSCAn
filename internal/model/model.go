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

// DependencyScope describes how packages from a selected module participate in
// the current build configuration.
type DependencyScope string

const (
	// ScopeRuntime means at least one affected package is loaded by production code.
	ScopeRuntime DependencyScope = "runtime"
	// ScopeTestOnly means affected packages are loaded only while building tests.
	ScopeTestOnly DependencyScope = "test-only"
	// ScopeGraphOnly means the module is selected but no package from it is loaded.
	ScopeGraphOnly DependencyScope = "graph-only"
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

// ModuleRequirement describes one requirement declared by a selected module's go.mod.
// Version is the version requested by that module; SelectedVersion is the version
// actually chosen for the build list by Go's module version selection.
type ModuleRequirement struct {
	Path            string `json:"path"`
	Version         string `json:"version,omitempty"`
	SelectedVersion string `json:"selected_version,omitempty"`
	Indirect        bool   `json:"indirect,omitempty"`
}

// Module describes one module in the selected Go build list.
type Module struct {
	Path                string              `json:"path"`
	Version             string              `json:"version,omitempty"`
	Kind                DependencyKind      `json:"kind"`
	Main                bool                `json:"main,omitempty"`
	Explicit            bool                `json:"explicit,omitempty"`
	IndirectRequirement bool                `json:"indirect_requirement,omitempty"`
	GoVersion           string              `json:"go_version,omitempty"`
	Deprecated          string              `json:"deprecated,omitempty"`
	Retracted           []string            `json:"retracted,omitempty"`
	ManifestAudited     bool                `json:"manifest_audited"`
	PackagesLoaded      bool                `json:"packages_loaded,omitempty"`
	Scope               DependencyScope     `json:"scope,omitempty"`
	Requires            []ModuleRequirement `json:"requires,omitempty"`
	Replace             *ModuleRef          `json:"replace,omitempty"`
	LocalReplacement    bool                `json:"local_replacement,omitempty"`
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
	ID              string           `json:"id"`
	Aliases         []string         `json:"aliases,omitempty"`
	Summary         string           `json:"summary,omitempty"`
	Details         string           `json:"details,omitempty"`
	CVEs            []string         `json:"cves,omitempty"`
	Fixed           string           `json:"fixed_version,omitempty"`
	CVSS            *CVSS            `json:"cvss,omitempty"`
	EPSS            *EPSS            `json:"epss,omitempty"`
	Severity        Severity         `json:"severity"`
	CWEs            []string         `json:"cwes,omitempty"`
	References      []string         `json:"references,omitempty"`
	Sources         []AdvisorySource `json:"sources,omitempty"`
	KnownExploited  bool             `json:"known_exploited,omitempty"`
	AffectedImports []AffectedImport `json:"affected_imports,omitempty"`
}

// AffectedImport identifies a vulnerable package and its vulnerable symbols.
type AffectedImport struct {
	Path    string   `json:"path"`
	Symbols []string `json:"symbols,omitempty"`
}

// Reachability is the strongest evidence available for a finding.
type Reachability string

const (
	// ReachabilityModule means only selected-module evidence is available.
	ReachabilityModule Reachability = "module"
	// ReachabilityPackage means an affected package is imported by the build.
	ReachabilityPackage Reachability = "package"
	// ReachabilitySymbol means a vulnerable symbol is present in analyzed code.
	ReachabilitySymbol Reachability = "symbol"
	// ReachabilityCalled means a call path reaches a vulnerable symbol.
	ReachabilityCalled Reachability = "called"
)

// CallFrame is one frame in a source-to-vulnerable-symbol call trace.
type CallFrame struct {
	Module   string `json:"module,omitempty"`
	Package  string `json:"package,omitempty"`
	Function string `json:"function,omitempty"`
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
}

// IgnoreRule is an auditable vulnerability exception.
type IgnoreRule struct {
	Reason  string `json:"reason" yaml:"reason"`
	Owner   string `json:"owner,omitempty" yaml:"owner,omitempty"`
	Expires string `json:"expires,omitempty" yaml:"expires,omitempty"`
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
	Module         Module             `json:"module"`
	Vulnerability  Vulnerability      `json:"vulnerability"`
	LatestVersion  string             `json:"latest_version,omitempty"`
	Paths          [][]ModuleRef      `json:"paths,omitempty"`
	Fix            *FixRecommendation `json:"fix,omitempty"`
	Ignored        bool               `json:"ignored,omitempty"`
	IgnoreRule     string             `json:"ignore_rule,omitempty"`
	IgnoreReason   string             `json:"ignore_reason,omitempty"`
	IgnoreOwner    string             `json:"ignore_owner,omitempty"`
	IgnoreExpires  string             `json:"ignore_expires,omitempty"`
	IgnoreExpired  bool               `json:"ignore_expired,omitempty"`
	Reachability   Reachability       `json:"reachability,omitempty"`
	CallStacks     [][]CallFrame      `json:"call_stacks,omitempty"`
	BaselineStatus string             `json:"baseline_status,omitempty"`
}

// GoHealth describes the main module's Go language and toolchain freshness.
type GoHealth struct {
	Directive            string `json:"directive,omitempty"`
	Toolchain            string `json:"toolchain,omitempty"`
	Latest               string `json:"latest,omitempty"`
	RecommendedDirective string `json:"recommended_directive,omitempty"`
	RecommendedToolchain string `json:"recommended_toolchain,omitempty"`
	DirectiveOutdated    bool   `json:"directive_outdated,omitempty"`
	ToolchainOutdated    bool   `json:"toolchain_outdated,omitempty"`
	// Unsupported means the release line named by Directive is outside Go's
	// support window; it does not imply that the active build toolchain is unsupported.
	Unsupported              bool `json:"unsupported,omitempty"`
	ToolchainUpgradeEligible bool `json:"toolchain_upgrade_eligible,omitempty"`
}

// DependencyHealth describes version and maintenance concerns for one selected dependency.
type DependencyHealth struct {
	Module            ModuleRef      `json:"module"`
	Kind              DependencyKind `json:"kind"`
	PackagesLoaded    bool           `json:"packages_loaded,omitempty"`
	Paths             [][]ModuleRef  `json:"paths,omitempty"`
	Repository        string         `json:"repository,omitempty"`
	RepositoryURL     string         `json:"repository_url,omitempty"`
	LatestVersion     string         `json:"latest_version,omitempty"`
	Outdated          bool           `json:"outdated,omitempty"`
	Deprecated        string         `json:"deprecated,omitempty"`
	Retracted         []string       `json:"retracted,omitempty"`
	Archived          bool           `json:"archived,omitempty"`
	Stale             bool           `json:"stale,omitempty"`
	Unmaintained      bool           `json:"unmaintained,omitempty"`
	MaintenanceNotice string         `json:"maintenance_notice,omitempty"`
	LastPush          time.Time      `json:"last_push,omitempty"`
}

// Summary contains dependency and vulnerability counts for a scan.
type Summary struct {
	Modules        int `json:"modules"`
	Direct         int `json:"direct"`
	Indirect       int `json:"indirect"`
	Transitive     int `json:"transitive"`
	Skipped        int `json:"skipped"`
	Manifests      int `json:"manifests"`
	ManifestErrors int `json:"manifest_errors"`

	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
	Ignored  int `json:"ignored"`

	OutdatedDependencies int `json:"outdated_dependencies"`
	Unmaintained         int `json:"unmaintained"`
	Archived             int `json:"archived"`
	Stale                int `json:"stale"`
	Deprecated           int `json:"deprecated"`
	Retracted            int `json:"retracted"`
	BaselineNew          int `json:"baseline_new,omitempty"`
	BaselineUnchanged    int `json:"baseline_unchanged,omitempty"`
	BaselineRegressed    int `json:"baseline_regressed,omitempty"`
	BaselineResolved     int `json:"baseline_resolved,omitempty"`
}

// Integrity describes scan-time module integrity verification.
type Integrity struct {
	Verified     bool   `json:"verified"`
	MissingGoSum bool   `json:"missing_go_sum,omitempty"`
	Error        string `json:"error,omitempty"`
}

// ResolvedFinding identifies a finding present in a baseline but absent now.
type ResolvedFinding struct {
	Module ModuleRef `json:"module"`
	ID     string    `json:"id"`
	Status string    `json:"status"`
}

// UpgradeChange describes one before/after version change.
type UpgradeChange struct {
	Component string `json:"component"`
	From      string `json:"from,omitempty"`
	To        string `json:"to,omitempty"`
}

// UpgradeSummary records the result of an applied upgrade operation.
type UpgradeSummary struct {
	Changes          []UpgradeChange   `json:"changes,omitempty"`
	ResolvedFindings []ResolvedFinding `json:"resolved_findings,omitempty"`
	NewFindings      []ResolvedFinding `json:"new_findings,omitempty"`
}

// Report is the complete result of a GoSCAn dependency vulnerability scan.
type Report struct {
	Root             string              `json:"-"`
	ToolVersion      string              `json:"tool_version"`
	Module           string              `json:"module"`
	MainRequirements []ModuleRequirement `json:"main_requirements,omitempty"`
	PackageAnalysis  bool                `json:"package_analysis"`
	ScannedAt        time.Time           `json:"scanned_at"`
	Summary          Summary             `json:"summary"`
	Dependencies     []Module            `json:"dependencies,omitempty"`
	Go               *GoHealth           `json:"go,omitempty"`
	Health           []DependencyHealth  `json:"health,omitempty"`
	Findings         []Finding           `json:"findings"`
	IgnoredFindings  []Finding           `json:"ignored_findings,omitempty"`
	Warnings         []string            `json:"warnings,omitempty"`
	Integrity        *Integrity          `json:"integrity,omitempty"`
	ResolvedFindings []ResolvedFinding   `json:"resolved_findings,omitempty"`
	UpgradePlan      []UpgradeChange     `json:"upgrade_plan,omitempty"`
	UpgradeResult    *UpgradeSummary     `json:"upgrade_result,omitempty"`
}
