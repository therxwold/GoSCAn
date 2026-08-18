package fixer

import (
	"fmt"

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
