package output

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"sort"
	"strings"
	"time"

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

// WriteOptions controls optional presentation of a report.
type WriteOptions struct {
	ShowIgnored   bool
	ShowManifests bool
}

// Write renders report in the requested output format.
func Write(w io.Writer, report *model.Report, format Format, options ...WriteOptions) error {
	var opts WriteOptions
	if len(options) > 0 {
		opts = options[0]
	}
	switch format {
	case FormatJSON:
		return writeJSON(w, report)
	case FormatSARIF:
		return writeSARIF(w, report, opts)
	default:
		return writeTerminal(w, report, opts)
	}
}

// writeJSON encodes the complete report as indented JSON.
func writeJSON(w io.Writer, report *model.Report) error {
	copy := *report
	if copy.SchemaVersion == 0 {
		copy.SchemaVersion = model.ReportSchemaVersion
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(&copy)
}

// writeTerminal renders the human-readable report and optional audit sections.
func writeTerminal(w io.Writer, r *model.Report, opts WriteOptions) error {
	fmt.Fprintf(w, "GoSCAn %s\n\n", r.ToolVersion)
	fmt.Fprintf(w, "Module: %s\n", r.Module)
	fmt.Fprintf(w, "Dependencies: %d total (%d direct, %d indirect, %d transitive", r.Summary.Modules, r.Summary.Direct, r.Summary.Indirect, r.Summary.Transitive)
	if r.Summary.Skipped > 0 {
		fmt.Fprintf(w, ", %d skipped", r.Summary.Skipped)
	}
	fmt.Fprintln(w, ")")
	fmt.Fprintf(w, "Manifests: %d/%d dependency go.mod files inspected", r.Summary.Manifests, r.Summary.Modules)
	if r.Summary.ManifestErrors > 0 {
		fmt.Fprintf(w, " (%d unavailable)", r.Summary.ManifestErrors)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Vulnerabilities: %d critical, %d high, %d medium, %d low, %d unknown", r.Summary.Critical, r.Summary.High, r.Summary.Medium, r.Summary.Low, r.Summary.Unknown)
	if r.Summary.Ignored > 0 {
		fmt.Fprintf(w, " (%d ignored)", r.Summary.Ignored)
	}
	fmt.Fprintln(w)
	writeGoHealth(w, r.Go)
	writeIntegrity(w, r.Integrity)
	writeDependencyHealth(w, r)
	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "\nNo active known vulnerabilities found.")
		if opts.ShowIgnored {
			writeIgnored(w, r.IgnoredFindings)
		}
		if opts.ShowManifests {
			writeManifests(w, r.Dependencies)
		}
		writeBaseline(w, r)
		writeUpgrade(w, r)
		writeWarnings(w, r)
		return nil
	}
	for _, f := range r.Findings {
		v := f.Vulnerability
		fmt.Fprintf(w, "\n%s  %s", strings.ToUpper(string(v.Severity)), v.ID)
		if f.BaselineStatus != "" {
			fmt.Fprintf(w, "  [%s]", strings.ToUpper(f.BaselineStatus))
		}
		fmt.Fprintln(w)
		if v.Summary != "" {
			fmt.Fprintf(w, "  %s\n", v.Summary)
		}
		fmt.Fprintf(w, "  Module:   %s@%s (%s)\n", f.Module.Path, f.Module.Version, f.Module.Kind)
		scope := f.Module.Scope
		if scope == "" && r.PackageAnalysis && !f.Module.PackagesLoaded {
			scope = model.ScopeGraphOnly
		}
		if scope != "" {
			fmt.Fprintf(w, "  Scope:    %s\n", scope)
		}
		if f.Reachability != "" {
			fmt.Fprintf(w, "  Evidence: %s\n", f.Reachability)
		}
		if f.IgnoreExpired {
			fmt.Fprintf(w, "  Exception: expired %s", f.IgnoreExpires)
			if f.IgnoreOwner != "" {
				fmt.Fprintf(w, " (owner: %s)", f.IgnoreOwner)
			}
			fmt.Fprintln(w)
		}
		if len(f.Vulnerability.AffectedImports) > 0 {
			for _, imported := range f.Vulnerability.AffectedImports {
				fmt.Fprintf(w, "  Affected: %s", imported.Path)
				if len(imported.Symbols) > 0 {
					fmt.Fprintf(w, " (%s)", strings.Join(imported.Symbols, ", "))
				}
				fmt.Fprintln(w)
			}
		}
		if len(f.CallStacks) > 0 {
			fmt.Fprintln(w, "  Call path:")
			for i, frame := range f.CallStacks[0] {
				prefix := "    "
				if i > 0 {
					prefix += "└── "
				}
				label := frame.Package
				if frame.Function != "" {
					label += "." + frame.Function
				}
				if frame.File != "" {
					label += fmt.Sprintf(" (%s:%d)", frame.File, frame.Line)
				}
				fmt.Fprintln(w, prefix+label)
			}
		}
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
		if origins := requirementOrigins(r, f.Module.Path); len(origins) > 0 {
			fmt.Fprintln(w, "  Declared by:")
			for _, origin := range origins {
				fmt.Fprintf(w, "    %s", origin.parent.Path)
				if origin.parent.Version != "" {
					fmt.Fprintf(w, "@%s", origin.parent.Version)
				}
				fmt.Fprintf(w, " requires %s@%s", f.Module.Path, origin.requirement.Version)
				if origin.requirement.SelectedVersion != "" && origin.requirement.SelectedVersion != origin.requirement.Version {
					fmt.Fprintf(w, " (selected %s)", origin.requirement.SelectedVersion)
				}
				fmt.Fprintln(w)
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
	if opts.ShowIgnored {
		writeIgnored(w, r.IgnoredFindings)
	}
	if opts.ShowManifests {
		writeManifests(w, r.Dependencies)
	}
	writeBaseline(w, r)
	writeUpgrade(w, r)
	writeWarnings(w, r)
	return nil
}

// writeBaseline renders baseline counts and resolved findings.
func writeBaseline(w io.Writer, report *model.Report) {
	if report.Summary.BaselineNew == 0 && report.Summary.BaselineUnchanged == 0 && report.Summary.BaselineRegressed == 0 && report.Summary.BaselineResolved == 0 {
		return
	}
	fmt.Fprintf(w, "\nBaseline: %d new, %d unchanged, %d regressed, %d resolved\n", report.Summary.BaselineNew, report.Summary.BaselineUnchanged, report.Summary.BaselineRegressed, report.Summary.BaselineResolved)
	for _, finding := range report.ResolvedFindings {
		fmt.Fprintf(w, "  RESOLVED  %s in %s@%s\n", finding.ID, finding.Module.Path, finding.Module.Version)
	}
}

// writeUpgrade renders latest-upgrade previews and applied before/after results.
func writeUpgrade(w io.Writer, report *model.Report) {
	if len(report.UpgradePlan) > 0 {
		fmt.Fprintln(w, "\nLatest upgrade plan:")
		for _, change := range report.UpgradePlan {
			writeUpgradeChange(w, change)
		}
	}
	if report.UpgradeResult == nil {
		return
	}
	fmt.Fprintln(w, "\nApplied upgrade result:")
	for _, change := range report.UpgradeResult.Changes {
		writeUpgradeChange(w, change)
	}
	fmt.Fprintf(w, "  vulnerabilities: %d resolved, %d introduced\n", len(report.UpgradeResult.ResolvedFindings), len(report.UpgradeResult.NewFindings))
}

// writeUpgradeChange renders an added, removed, or updated component version.
func writeUpgradeChange(w io.Writer, change model.UpgradeChange) {
	from, to := change.From, change.To
	if from == "" {
		from = "(added)"
	}
	if to == "" {
		to = "(removed)"
	}
	fmt.Fprintf(w, "  %s: %s -> %s\n", change.Component, from, to)
}

// requirementOrigin links a selected module requirement to the manifest declaring it.
type requirementOrigin struct {
	parent      model.ModuleRef
	requirement model.ModuleRequirement
}

// requirementOrigins finds every inspected manifest that declares target.
func requirementOrigins(report *model.Report, target string) []requirementOrigin {
	var out []requirementOrigin
	for _, requirement := range report.MainRequirements {
		if requirement.Path == target {
			out = append(out, requirementOrigin{parent: model.ModuleRef{Path: report.Module}, requirement: requirement})
		}
	}
	for _, module := range report.Dependencies {
		for _, requirement := range module.Requires {
			if requirement.Path != target {
				continue
			}
			out = append(out, requirementOrigin{
				parent:      model.ModuleRef{Path: module.Path, Version: module.Version},
				requirement: requirement,
			})
		}
	}
	return out
}

// writeManifests renders selected dependency manifest requirements.
func writeManifests(w io.Writer, modules []model.Module) {
	if len(modules) == 0 {
		return
	}
	fmt.Fprintln(w, "\nDependency manifests:")
	for _, module := range modules {
		fmt.Fprintf(w, "  %s@%s (%s", module.Path, module.Version, module.Kind)
		if module.GoVersion != "" {
			fmt.Fprintf(w, ", go %s", module.GoVersion)
		}
		if !module.ManifestAudited {
			fmt.Fprint(w, ", manifest audit unavailable")
		}
		fmt.Fprintln(w, ")")
		if len(module.Requires) == 0 {
			if module.ManifestAudited {
				fmt.Fprintln(w, "    requires: none")
			} else {
				fmt.Fprintln(w, "    requires: no complete manifest data")
			}
			continue
		}
		for _, requirement := range module.Requires {
			fmt.Fprintf(w, "    requires %s@%s", requirement.Path, requirement.Version)
			if requirement.Indirect {
				fmt.Fprint(w, " (indirect)")
			}
			switch {
			case requirement.SelectedVersion == "":
				fmt.Fprint(w, " -> not selected")
			case requirement.SelectedVersion != requirement.Version:
				fmt.Fprintf(w, " -> selected %s", requirement.SelectedVersion)
			}
			fmt.Fprintln(w)
		}
	}
}

// writeGoHealth renders Go directive and toolchain freshness information.
func writeGoHealth(w io.Writer, health *model.GoHealth) {
	if health == nil {
		return
	}
	fmt.Fprintln(w, "\nGo version:")
	if health.Directive == "" {
		fmt.Fprintf(w, "  go directive: unavailable (latest stable %s)\n", health.Latest)
	} else if health.DirectiveOutdated {
		status := "outdated"
		if health.Unsupported {
			status = "directive predates supported release lines"
		}
		fmt.Fprintf(w, "  go:        %s -> %s (%s; latest stable %s)\n", health.Directive, health.RecommendedDirective, status, health.Latest)
	} else {
		fmt.Fprintf(w, "  go:        %s (current; latest stable %s)\n", health.Directive, health.Latest)
	}
	if health.Toolchain != "" {
		switch {
		case health.Toolchain == "default":
			fmt.Fprintln(w, "  toolchain: default (automatic toolchain switching disabled)")
		case health.ToolchainOutdated:
			fmt.Fprintf(w, "  toolchain: %s -> %s\n", health.Toolchain, health.RecommendedToolchain)
		default:
			fmt.Fprintf(w, "  toolchain: %s (current)\n", health.Toolchain)
		}
	}
}

// writeIntegrity renders module checksum and cache verification status.
func writeIntegrity(w io.Writer, integrity *model.Integrity) {
	if integrity == nil {
		return
	}
	fmt.Fprintln(w, "\nModule integrity:")
	switch {
	case integrity.Error != "":
		fmt.Fprintf(w, "  FAILED: %s\n", integrity.Error)
	case integrity.Verified:
		fmt.Fprintln(w, "  verified by go mod verify")
	default:
		fmt.Fprintln(w, "  not verified")
	}
	if integrity.MissingGoSum {
		fmt.Fprintln(w, "  warning: go.sum is missing despite selected dependencies")
	}
}

// writeDependencyHealth renders maintenance, retraction, and version findings.
func writeDependencyHealth(w io.Writer, r *model.Report) {
	if len(r.Health) == 0 {
		return
	}
	fmt.Fprintf(w, "\nDependency health: %d unmaintained, %d archived, %d stale, %d deprecated, %d retracted, %d outdated\n",
		r.Summary.Unmaintained, r.Summary.Archived, r.Summary.Stale, r.Summary.Deprecated, r.Summary.Retracted, r.Summary.OutdatedDependencies)
	for _, health := range r.Health {
		labels := make([]string, 0, 5)
		if health.Unmaintained {
			labels = append(labels, "UNMAINTAINED")
		}
		if health.Archived {
			labels = append(labels, "ARCHIVED")
		}
		if health.Deprecated != "" {
			labels = append(labels, "DEPRECATED")
		}
		if len(health.Retracted) > 0 {
			labels = append(labels, "RETRACTED")
		}
		if health.Stale {
			labels = append(labels, "STALE")
		}
		if health.Outdated {
			labels = append(labels, "OUTDATED")
		}
		fmt.Fprintf(w, "  %s  %s@%s", strings.Join(labels, "/"), health.Module.Path, health.Module.Version)
		if health.Kind != "" {
			kind := string(health.Kind)
			scope := model.DependencyScope("")
			for _, module := range r.Dependencies {
				if module.Path == health.Module.Path {
					scope = module.Scope
					if scope == "" && r.PackageAnalysis && !module.PackagesLoaded {
						scope = model.ScopeGraphOnly
					}
					break
				}
			}
			if scope == "" && r.PackageAnalysis && !health.PackagesLoaded {
				scope = model.ScopeGraphOnly
			}
			if scope != "" {
				kind += ", " + string(scope)
			}
			fmt.Fprintf(w, " (%s)", kind)
		}
		fmt.Fprintln(w)
		if health.LatestVersion != "" && health.Outdated {
			fmt.Fprintf(w, "    Latest: %s\n", health.LatestVersion)
		}
		if health.RepositoryURL != "" {
			fmt.Fprintf(w, "    Repo:   %s\n", health.RepositoryURL)
		}
		if !health.LastPush.IsZero() && health.Stale {
			fmt.Fprintf(w, "    Last push: %s\n", health.LastPush.UTC().Format("2006-01-02"))
		}
		if health.MaintenanceNotice != "" {
			fmt.Fprintf(w, "    Notice: repository explicitly says %q\n", health.MaintenanceNotice)
		}
		for _, reason := range health.Retracted {
			fmt.Fprintf(w, "    Retraction: %s\n", reason)
		}
		if len(health.Paths) > 0 {
			fmt.Fprintln(w, "    Path:")
			for i, ref := range health.Paths[0] {
				prefix := "      "
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
		if health.Deprecated != "" {
			fmt.Fprintf(w, "    Deprecated: %s\n", health.Deprecated)
		}
	}
}

// writeIgnored renders suppressed findings with their exception audit metadata.
func writeIgnored(w io.Writer, findings []model.Finding) {
	if len(findings) == 0 {
		return
	}
	fmt.Fprintln(w, "\nIgnored / false positives:")
	for _, f := range findings {
		fmt.Fprintf(w, "  %s  %s@%s\n", f.Vulnerability.ID, f.Module.Path, f.Module.Version)
		fmt.Fprintf(w, "    Rule:   %s\n", f.IgnoreRule)
		fmt.Fprintf(w, "    Reason: %s\n", f.IgnoreReason)
		if f.IgnoreOwner != "" {
			fmt.Fprintf(w, "    Owner:  %s\n", f.IgnoreOwner)
		}
		if f.IgnoreExpires != "" {
			fmt.Fprintf(w, "    Expires: %s\n", f.IgnoreExpires)
		}
	}
}

// writeWarnings renders non-fatal scan diagnostics.
func writeWarnings(w io.Writer, r *model.Report) {
	if len(r.Warnings) == 0 {
		return
	}
	fmt.Fprintln(w, "\nWarnings:")
	for _, warning := range r.Warnings {
		fmt.Fprintf(w, "  - %s\n", warning)
	}
}

// sarifLog is the top-level SARIF 2.1.0 document.
type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

// sarifRun contains one GoSCAn tool execution and its results.
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

// sarifTool describes the SARIF analysis tool.
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

// sarifDriver contains GoSCAn identity and rule metadata.
type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules,omitempty"`
}

// sarifRule defines one advisory or health rule emitted in SARIF.
type sarifRule struct {
	ID               string       `json:"id"`
	ShortDescription sarifMessage `json:"shortDescription"`
}

// sarifMessage wraps human-readable SARIF text.
type sarifMessage struct {
	Text string `json:"text"`
}

// sarifResult is one vulnerability, health, or integrity result.
type sarifResult struct {
	RuleID       string             `json:"ruleId"`
	Level        string             `json:"level"`
	Message      sarifMessage       `json:"message"`
	Locations    []sarifLocation    `json:"locations,omitempty"`
	Properties   map[string]any     `json:"properties,omitempty"`
	Suppressions []sarifSuppression `json:"suppressions,omitempty"`
}

// sarifSuppression records an accepted external finding exception.
type sarifSuppression struct {
	Kind          string `json:"kind"`
	Status        string `json:"status,omitempty"`
	Justification string `json:"justification,omitempty"`
}

// sarifLocation identifies the physical artifact associated with a result.
type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

// sarifPhysicalLocation wraps a SARIF artifact reference.
type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

// sarifArtifactLocation stores the URI of the affected project artifact.
type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

// writeSARIF converts report findings and health signals into SARIF 2.1.0.
func writeSARIF(w io.Writer, r *model.Report, opts WriteOptions) error {
	findings := append([]model.Finding(nil), r.Findings...)
	if opts.ShowIgnored {
		// SARIF suppressions must be emitted as results; ignored findings otherwise
		// remain absent from the result stream.
		findings = append(findings, r.IgnoredFindings...)
	}

	rules := map[string]sarifRule{}
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		v := f.Vulnerability
		rules[v.ID] = sarifRule{ID: v.ID, ShortDescription: sarifMessage{Text: v.Summary}}
		props := map[string]any{"module": f.Module.Path, "version": f.Module.Version, "dependencyKind": f.Module.Kind}
		if f.Module.Scope != "" {
			props["scope"] = f.Module.Scope
		}
		if f.Reachability != "" {
			props["reachability"] = f.Reachability
		}
		if len(f.CallStacks) > 0 {
			props["callStacks"] = f.CallStacks
		}
		if len(v.AffectedImports) > 0 {
			props["affectedImports"] = v.AffectedImports
		}
		if f.BaselineStatus != "" {
			props["baselineStatus"] = f.BaselineStatus
		}
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
		if f.Ignored {
			props["ignored"] = true
			props["ignoreRule"] = f.IgnoreRule
			props["ignoreReason"] = f.IgnoreReason
			if f.IgnoreOwner != "" {
				props["ignoreOwner"] = f.IgnoreOwner
			}
			if f.IgnoreExpires != "" {
				props["ignoreExpires"] = f.IgnoreExpires
			}
		}
		msg := fmt.Sprintf("%s affects %s@%s", v.ID, f.Module.Path, f.Module.Version)
		if v.Fixed != "" {
			msg += ", fixed in " + v.Fixed
		}
		result := sarifResult{RuleID: v.ID, Level: sarifLevel(v.Severity), Message: sarifMessage{Text: msg}, Locations: []sarifLocation{sarifGoModLocation()}, Properties: props}
		if f.Ignored {
			result.Suppressions = []sarifSuppression{{Kind: "external", Status: "accepted", Justification: f.IgnoreReason}}
		}
		results = append(results, result)
	}
	if r.Go != nil {
		if r.Go.Unsupported {
			addSARIFHealth(rules, &results, "GOSCAN-GO-UNSUPPORTED", "error",
				fmt.Sprintf("go directive %s is outside the two currently supported Go release lines; upgrade to %s", r.Go.Directive, r.Go.RecommendedDirective),
				map[string]any{"current": r.Go.Directive, "recommended": r.Go.RecommendedDirective, "latest": r.Go.Latest})
		} else if r.Go.DirectiveOutdated {
			addSARIFHealth(rules, &results, "GOSCAN-GO-OUTDATED", "warning",
				fmt.Sprintf("go directive %s can be upgraded to %s", r.Go.Directive, r.Go.RecommendedDirective),
				map[string]any{"current": r.Go.Directive, "recommended": r.Go.RecommendedDirective, "latest": r.Go.Latest})
		}
		if r.Go.ToolchainOutdated {
			addSARIFHealth(rules, &results, "GOSCAN-TOOLCHAIN-OUTDATED", "warning",
				fmt.Sprintf("toolchain %s can be upgraded to %s", r.Go.Toolchain, r.Go.RecommendedToolchain),
				map[string]any{"current": r.Go.Toolchain, "recommended": r.Go.RecommendedToolchain})
		}
	}
	for _, health := range r.Health {
		// Health signals use synthetic rule IDs so consumers can independently
		// filter maintenance, version, and vulnerability results.
		props := map[string]any{"module": health.Module.Path, "version": health.Module.Version, "kind": health.Kind}
		if len(health.Paths) > 0 {
			props["dependencyPaths"] = health.Paths
		}
		if health.RepositoryURL != "" {
			props["repository"] = health.RepositoryURL
		}
		if health.Unmaintained {
			message := fmt.Sprintf("%s@%s is unmaintained", health.Module.Path, health.Module.Version)
			if health.MaintenanceNotice != "" {
				message += ": " + health.MaintenanceNotice
			}
			addSARIFHealth(rules, &results, "GOSCAN-DEPENDENCY-UNMAINTAINED", "warning", message, props)
		} else if health.Archived {
			addSARIFHealth(rules, &results, "GOSCAN-DEPENDENCY-ARCHIVED", "warning",
				fmt.Sprintf("%s@%s repository is archived", health.Module.Path, health.Module.Version), props)
		}
		if health.Deprecated != "" {
			deprecatedProps := cloneProperties(props)
			deprecatedProps["deprecation"] = health.Deprecated
			addSARIFHealth(rules, &results, "GOSCAN-DEPENDENCY-DEPRECATED", "warning",
				fmt.Sprintf("%s@%s is deprecated: %s", health.Module.Path, health.Module.Version, health.Deprecated), deprecatedProps)
		}
		if len(health.Retracted) > 0 {
			retractedProps := cloneProperties(props)
			retractedProps["retractions"] = health.Retracted
			addSARIFHealth(rules, &results, "GOSCAN-DEPENDENCY-RETRACTED", "warning",
				fmt.Sprintf("%s@%s is retracted", health.Module.Path, health.Module.Version), retractedProps)
		}
		if health.Stale && !health.Unmaintained {
			staleProps := cloneProperties(props)
			if !health.LastPush.IsZero() {
				staleProps["lastPush"] = health.LastPush.UTC().Format(time.RFC3339)
			}
			addSARIFHealth(rules, &results, "GOSCAN-DEPENDENCY-STALE", "note",
				fmt.Sprintf("%s@%s has not received a recent repository push", health.Module.Path, health.Module.Version), staleProps)
		}
		if health.Outdated {
			outdatedProps := cloneProperties(props)
			outdatedProps["latestVersion"] = health.LatestVersion
			addSARIFHealth(rules, &results, "GOSCAN-DEPENDENCY-OUTDATED", "note",
				fmt.Sprintf("%s@%s has newer version %s", health.Module.Path, health.Module.Version, health.LatestVersion), outdatedProps)
		}
	}
	if r.Integrity != nil {
		if r.Integrity.Error != "" {
			addSARIFHealth(rules, &results, "GOSCAN-MODULE-INTEGRITY", "error",
				"go mod verify failed: "+r.Integrity.Error, map[string]any{"verified": false})
		} else if r.Integrity.MissingGoSum {
			addSARIFHealth(rules, &results, "GOSCAN-MISSING-GO-SUM", "warning",
				"go.sum is missing despite selected dependencies", map[string]any{"verified": r.Integrity.Verified})
		}
	}

	ruleList := make([]sarifRule, 0, len(rules))
	for _, rule := range rules {
		ruleList = append(ruleList, rule)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })
	log := sarifLog{Version: "2.1.0", Schema: "https://json.schemastore.org/sarif-2.1.0.json", Runs: []sarifRun{{Tool: sarifTool{Driver: sarifDriver{Name: "GoSCAn", Version: r.ToolVersion, Rules: ruleList}}, Results: results}}}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// addSARIFHealth registers a synthetic health rule and appends its result.
func addSARIFHealth(rules map[string]sarifRule, results *[]sarifResult, id, level, message string, properties map[string]any) {
	rules[id] = sarifRule{ID: id, ShortDescription: sarifMessage{Text: message}}
	*results = append(*results, sarifResult{
		RuleID:     id,
		Level:      level,
		Message:    sarifMessage{Text: message},
		Locations:  []sarifLocation{sarifGoModLocation()},
		Properties: properties,
	})
}

// sarifGoModLocation returns a repository-root-relative go.mod artifact location.
func sarifGoModLocation() sarifLocation {
	return sarifLocation{PhysicalLocation: sarifPhysicalLocation{
		ArtifactLocation: sarifArtifactLocation{URI: "go.mod", URIBaseID: "%SRCROOT%"},
	}}
}

// cloneProperties returns a shallow copy safe for result-specific augmentation.
func cloneProperties(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	maps.Copy(out, in)
	return out
}

// sarifLevel maps normalized vulnerability severity to a SARIF result level.
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
