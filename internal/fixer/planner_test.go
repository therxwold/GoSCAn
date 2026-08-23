package fixer

import (
	"testing"

	"github.com/therxwold/GoSCAn/internal/model"
)

// TestRecommendTransitivePin verifies minimal MVS remediation for a transitive dependency.
func TestRecommendTransitivePin(t *testing.T) {
	m := model.Module{Path: "golang.org/x/net", Version: "v0.20.0", Kind: model.DependencyTransitive}
	got := Recommend(m, "v0.25.0", "v0.44.0")
	if got == nil || got.Strategy != model.FixTransitivePin {
		t.Fatalf("got=%+v", got)
	}
	if got.GoModChange == nil || got.GoModChange.Line != "require golang.org/x/net v0.25.0 // indirect" {
		t.Fatalf("gomod=%+v", got.GoModChange)
	}
}

// TestRecommendDirect verifies direct dependency upgrade recommendations.
func TestRecommendDirect(t *testing.T) {
	m := model.Module{Path: "example.com/a", Version: "v1.0.0", Kind: model.DependencyDirect}
	got := Recommend(m, "v1.0.1", "v1.2.0")
	if got.Strategy != model.FixDirectUpgrade || got.GoModChange == nil || got.GoModChange.Indirect {
		t.Fatalf("got=%+v", got)
	}
}

// TestRecommendSkipsReplacement verifies conservative replacement handling.
func TestRecommendSkipsReplacement(t *testing.T) {
	m := model.Module{Path: "example.com/a", Version: "v1.0.0", Kind: model.DependencyTransitive, Replace: &model.ModuleRef{Path: "example.com/fork", Version: "v1.0.1"}}
	if got := Recommend(m, "v1.0.2", "v1.0.3"); got != nil {
		t.Fatalf("got=%+v", got)
	}
}

// TestRecommendIndirectRequirementUsesSafePin verifies explicit indirect MVS pins.
func TestRecommendIndirectRequirementUsesSafePin(t *testing.T) {
	m := model.Module{Path: "example.com/indirect", Version: "v1.0.0", Kind: model.DependencyIndirect}
	got := Recommend(m, "v1.0.4", "v1.2.0")
	if got == nil || got.Strategy != model.FixTransitivePin {
		t.Fatalf("got=%+v", got)
	}
	if got.GoModChange == nil || !got.GoModChange.Indirect || got.GoModChange.Line != "require example.com/indirect v1.0.4 // indirect" {
		t.Fatalf("go.mod=%+v", got.GoModChange)
	}
}

// TestRecommendNoFixedVersion verifies that unknown fixes are not fabricated.
func TestRecommendNoFixedVersion(t *testing.T) {
	m := model.Module{Path: "example.com/a", Version: "v1.0.0", Kind: model.DependencyDirect}
	if got := Recommend(m, "", "v1.2.0"); got != nil {
		t.Fatalf("got=%+v", got)
	}
}

// TestLatestRecommendationsUpgradeLoadedModulesAndSkipGraphOnly verifies scope limits.
func TestLatestRecommendationsUpgradeLoadedModulesAndSkipGraphOnly(t *testing.T) {
	report := &model.Report{
		PackageAnalysis: true,
		Dependencies: []model.Module{
			{Path: "example.com/loaded", Version: "v1.0.0", Kind: model.DependencyDirect, PackagesLoaded: true},
			{Path: "example.com/tooling", Version: "v1.0.0", Kind: model.DependencyTransitive},
			{Path: "example.com/replaced", Version: "v1.0.0", Kind: model.DependencyDirect, PackagesLoaded: true, Replace: &model.ModuleRef{Path: "example.com/fork", Version: "v1.0.0"}},
		},
		Health: []model.DependencyHealth{
			{Module: model.ModuleRef{Path: "example.com/loaded", Version: "v1.0.0"}, Outdated: true, LatestVersion: "v1.4.0"},
			{Module: model.ModuleRef{Path: "example.com/tooling", Version: "v1.0.0"}, Outdated: true, LatestVersion: "v1.5.0"},
			{Module: model.ModuleRef{Path: "example.com/replaced", Version: "v1.0.0"}, Outdated: true, LatestVersion: "v2.0.0"},
		},
	}
	got := LatestRecommendations(report, false)
	if len(got) != 1 || got[0].Fix == nil || got[0].Fix.Module != "example.com/loaded" || got[0].Fix.To != "v1.4.0" {
		t.Fatalf("recommendations=%+v", got)
	}
}

// TestLatestRecommendationsUseNewestVulnerabilityVersion verifies latest remediation selection.
func TestLatestRecommendationsUseNewestVulnerabilityVersion(t *testing.T) {
	report := &model.Report{Findings: []model.Finding{
		{
			Module:        model.Module{Path: "example.com/a", Version: "v1.0.0"},
			LatestVersion: "v2.0.0",
			Fix:           &model.FixRecommendation{Module: "example.com/a", To: "v1.2.3"},
		},
		{
			Module: model.Module{Path: "example.com/b", Version: "v1.0.0"},
			Fix:    &model.FixRecommendation{Module: "example.com/b", To: "v1.1.0"},
		},
	}}
	got := LatestRecommendations(report, true)
	if len(got) != 2 || got[0].Fix.To != "v2.0.0" || got[1].Fix.To != "v1.1.0" {
		t.Fatalf("recommendations=%+v", got)
	}
	if got := LatestRecommendations(report, false); len(got) != 0 {
		t.Fatalf("vulnerability upgrades should be disabled: %+v", got)
	}
}

// TestLatestRecommendationsRemainConservativeWithoutPackageAnalysis verifies fallback planning.
func TestLatestRecommendationsRemainConservativeWithoutPackageAnalysis(t *testing.T) {
	report := &model.Report{
		Dependencies: []model.Module{{Path: "example.com/a", Version: "v1.0.0"}},
		Health:       []model.DependencyHealth{{Module: model.ModuleRef{Path: "example.com/a"}, Outdated: true, LatestVersion: "v1.2.0"}},
	}
	if got := LatestRecommendations(report, false); len(got) != 1 {
		t.Fatalf("recommendations=%+v", got)
	}
}

// TestLatestPlanIncludesDependenciesAndGoSettings verifies complete preview generation.
func TestLatestPlanIncludesDependenciesAndGoSettings(t *testing.T) {
	report := &model.Report{
		Dependencies: []model.Module{{Path: "example.com/a", Version: "v1.0.0", PackagesLoaded: true}},
		Health:       []model.DependencyHealth{{Module: model.ModuleRef{Path: "example.com/a"}, Outdated: true, LatestVersion: "v1.2.0"}},
		Go: &model.GoHealth{
			Directive: "1.25", RecommendedDirective: "1.27", DirectiveOutdated: true,
			Toolchain: "go1.25.0", RecommendedToolchain: "go1.27.0", ToolchainOutdated: true, ToolchainUpgradeEligible: true,
		},
	}
	plan := LatestPlan(report, false)
	if len(plan) != 3 {
		t.Fatalf("plan=%+v", plan)
	}
}

// TestUpgradeDiffReportsVersionAndFindingChanges verifies before-and-after classification.
func TestUpgradeDiffReportsVersionAndFindingChanges(t *testing.T) {
	before := &model.Report{
		Dependencies: []model.Module{{Path: "example.com/a", Version: "v1.0.0"}},
		Findings:     []model.Finding{{Module: model.Module{Path: "example.com/a", Version: "v1.0.0"}, Vulnerability: model.Vulnerability{ID: "GO-1"}}},
	}
	after := &model.Report{
		Dependencies: []model.Module{{Path: "example.com/a", Version: "v1.2.0"}},
		Findings:     []model.Finding{{Module: model.Module{Path: "example.com/a", Version: "v1.2.0"}, Vulnerability: model.Vulnerability{ID: "GO-2"}}},
	}
	diff := UpgradeDiff(before, after)
	if len(diff.Changes) != 1 || len(diff.ResolvedFindings) != 1 || diff.ResolvedFindings[0].ID != "GO-1" || len(diff.NewFindings) != 1 || diff.NewFindings[0].ID != "GO-2" {
		t.Fatalf("diff=%+v", diff)
	}
}
