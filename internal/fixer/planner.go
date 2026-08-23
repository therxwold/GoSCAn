package fixer

import (
	"fmt"
	"sort"

	"github.com/therxwold/GoSCAn/internal/goversion"
	"github.com/therxwold/GoSCAn/internal/model"
)

// Recommend builds the smallest go.mod remediation GoSCAn can safely propose for a module.
func Recommend(m model.Module, fixed, latest string) *model.FixRecommendation {
	if fixed == "" || m.Main || m.LocalReplacement {
		return nil
	}
	if m.Replace != nil {
		return nil // Replacement directives need explicit handling; do not guess.
	}

	strategy := model.FixTransitivePin
	reason := "pin the first fixed version in the main module so Go MVS selects it across the dependency graph"
	gomod := &model.GoModChange{
		Module:   m.Path,
		Version:  fixed,
		Indirect: true,
		Line:     fmt.Sprintf("require %s %s // indirect", m.Path, fixed),
	}

	if m.Kind == model.DependencyDirect {
		strategy = model.FixDirectUpgrade
		reason = "upgrade the directly required module to the first fixed version"
		gomod = &model.GoModChange{
			Module:   m.Path,
			Version:  fixed,
			Indirect: false,
			Line:     fmt.Sprintf("require %s %s", m.Path, fixed),
		}
	}

	return &model.FixRecommendation{
		Strategy:      strategy,
		Module:        m.Path,
		From:          m.Version,
		To:            fixed,
		Command:       fmt.Sprintf("go get %s@%s", m.Path, fixed),
		Reason:        reason,
		GoModChange:   gomod,
		LatestVersion: latest,
	}
}

// LatestRecommendations returns upgrades to the newest resolved versions.
// When package analysis succeeded, graph-only modules are intentionally left to
// their loaded parents so the main go.mod is not polluted with tooling pins.
func LatestRecommendations(report *model.Report, includeVulnerabilities bool) []model.Finding {
	if report == nil {
		return nil
	}
	modules := make(map[string]model.Module, len(report.Dependencies))
	for _, module := range report.Dependencies {
		modules[module.Path] = module
	}
	versions := map[string]string{}
	for _, health := range report.Health {
		module, ok := modules[health.Module.Path]
		if !ok || !health.Outdated || health.LatestVersion == "" || module.Replace != nil {
			continue
		}
		// Let loaded parents move graph-only dependencies transitively instead of
		// polluting the main go.mod with direct tooling pins.
		if report.PackageAnalysis && !module.PackagesLoaded {
			continue
		}
		versions[module.Path] = goversion.Max(versions[module.Path], health.LatestVersion)
	}
	if includeVulnerabilities {
		for _, finding := range report.Findings {
			if finding.Module.Replace != nil || finding.Module.LocalReplacement {
				continue
			}
			version := finding.LatestVersion
			if version == "" && finding.Fix != nil {
				version = finding.Fix.To
			}
			if version != "" {
				versions[finding.Module.Path] = goversion.Max(versions[finding.Module.Path], version)
				modules[finding.Module.Path] = finding.Module
			}
		}
	}

	paths := make([]string, 0, len(versions))
	for path := range versions {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	findings := make([]model.Finding, 0, len(paths))
	for _, path := range paths {
		module := modules[path]
		findings = append(findings, model.Finding{
			Module: module,
			Fix: &model.FixRecommendation{
				Module:        path,
				From:          module.Version,
				To:            versions[path],
				Command:       fmt.Sprintf("go get %s@%s", path, versions[path]),
				LatestVersion: versions[path],
			},
		})
	}
	return findings
}

// LatestPlan renders the dependency and Go changes proposed by latest mode.
func LatestPlan(report *model.Report, includeVulnerabilities bool) []model.UpgradeChange {
	var changes []model.UpgradeChange
	for _, finding := range LatestRecommendations(report, includeVulnerabilities) {
		changes = append(changes, model.UpgradeChange{Component: finding.Module.Path, From: finding.Module.Version, To: finding.Fix.To})
	}
	if report != nil && report.Go != nil {
		if report.Go.DirectiveOutdated && report.Go.RecommendedDirective != "" {
			changes = append(changes, model.UpgradeChange{Component: "go directive", From: report.Go.Directive, To: report.Go.RecommendedDirective})
		}
		if report.Go.ToolchainUpgradeEligible && report.Go.ToolchainOutdated && report.Go.RecommendedToolchain != "" {
			changes = append(changes, model.UpgradeChange{Component: "toolchain", From: report.Go.Toolchain, To: report.Go.RecommendedToolchain})
		}
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Component < changes[j].Component })
	return changes
}

// UpgradeDiff compares the selected graph and active findings before and after an apply.
func UpgradeDiff(before, after *model.Report) *model.UpgradeSummary {
	result := &model.UpgradeSummary{}
	if before == nil || after == nil {
		return result
	}
	beforeModules, afterModules := map[string]string{}, map[string]string{}
	for _, module := range before.Dependencies {
		beforeModules[module.Path] = module.Version
	}
	for _, module := range after.Dependencies {
		afterModules[module.Path] = module.Version
	}
	for path, from := range beforeModules {
		to, present := afterModules[path]
		if !present {
			result.Changes = append(result.Changes, model.UpgradeChange{Component: path, From: from})
		} else if to != from {
			result.Changes = append(result.Changes, model.UpgradeChange{Component: path, From: from, To: to})
		}
	}
	for path, to := range afterModules {
		if _, present := beforeModules[path]; !present {
			result.Changes = append(result.Changes, model.UpgradeChange{Component: path, To: to})
		}
	}
	if before.Go != nil && after.Go != nil {
		if before.Go.Directive != after.Go.Directive {
			result.Changes = append(result.Changes, model.UpgradeChange{Component: "go directive", From: before.Go.Directive, To: after.Go.Directive})
		}
		if before.Go.Toolchain != after.Go.Toolchain {
			result.Changes = append(result.Changes, model.UpgradeChange{Component: "toolchain", From: before.Go.Toolchain, To: after.Go.Toolchain})
		}
	}
	beforeFindings, afterFindings := findingSet(before), findingSet(after)
	for key, finding := range beforeFindings {
		if _, ok := afterFindings[key]; !ok {
			result.ResolvedFindings = append(result.ResolvedFindings, finding)
		}
	}
	for key, finding := range afterFindings {
		if _, ok := beforeFindings[key]; !ok {
			result.NewFindings = append(result.NewFindings, finding)
		}
	}
	sort.Slice(result.Changes, func(i, j int) bool { return result.Changes[i].Component < result.Changes[j].Component })
	sort.Slice(result.ResolvedFindings, func(i, j int) bool {
		if result.ResolvedFindings[i].Module.Path != result.ResolvedFindings[j].Module.Path {
			return result.ResolvedFindings[i].Module.Path < result.ResolvedFindings[j].Module.Path
		}
		return result.ResolvedFindings[i].ID < result.ResolvedFindings[j].ID
	})
	sort.Slice(result.NewFindings, func(i, j int) bool {
		if result.NewFindings[i].Module.Path != result.NewFindings[j].Module.Path {
			return result.NewFindings[i].Module.Path < result.NewFindings[j].Module.Path
		}
		return result.NewFindings[i].ID < result.NewFindings[j].ID
	})
	return result
}

// findingSet indexes active findings by stable module-and-advisory identity.
func findingSet(report *model.Report) map[string]model.ResolvedFinding {
	out := map[string]model.ResolvedFinding{}
	for _, finding := range report.Findings {
		key := finding.Module.Path + "\x00" + finding.Vulnerability.ID
		out[key] = model.ResolvedFinding{Module: model.ModuleRef{Path: finding.Module.Path, Version: finding.Module.Version}, ID: finding.Vulnerability.ID}
	}
	return out
}
