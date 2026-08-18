package fixer

import (
	"github.com/therxwold/GoSCAn/internal/model"
	"testing"
)

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
func TestRecommendDirect(t *testing.T) {
	m := model.Module{Path: "example.com/a", Version: "v1.0.0", Kind: model.DependencyDirect}
	got := Recommend(m, "v1.0.1", "v1.2.0")
	if got.Strategy != model.FixDirectUpgrade || got.GoModChange == nil || got.GoModChange.Indirect {
		t.Fatalf("got=%+v", got)
	}
}
func TestRecommendSkipsReplacement(t *testing.T) {
	m := model.Module{Path: "example.com/a", Version: "v1.0.0", Kind: model.DependencyTransitive, Replace: &model.ModuleRef{Path: "example.com/fork", Version: "v1.0.1"}}
	if got := Recommend(m, "v1.0.2", "v1.0.3"); got != nil {
		t.Fatalf("got=%+v", got)
	}
}

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

func TestRecommendNoFixedVersion(t *testing.T) {
	m := model.Module{Path: "example.com/a", Version: "v1.0.0", Kind: model.DependencyDirect}
	if got := Recommend(m, "", "v1.2.0"); got != nil {
		t.Fatalf("got=%+v", got)
	}
}
