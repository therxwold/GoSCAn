package dependency

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/therxwold/GoSCAn/internal/model"
)

// fakeRunner returns command output keyed by the complete invocation.
type fakeRunner map[string][]byte

// Run implements command.Runner for deterministic loader tests.
func (f fakeRunner) Run(_ context.Context, _ string, name string, args ...string) ([]byte, error) {
	key := name + " " + strings.Join(args, " ")
	v, ok := f[key]
	if !ok {
		return nil, fmt.Errorf("unexpected command %s", key)
	}
	return v, nil
}

// TestLoaderClassifiesEverySelectedModule verifies module kinds, scopes, manifests, and integrity.
func TestLoaderClassifiesEverySelectedModule(t *testing.T) {
	dir := t.TempDir()
	mainMod := filepath.Join(dir, "go.mod")
	directMod := filepath.Join(dir, "direct.mod")
	indirectMod := filepath.Join(dir, "indirect.mod")
	deepMod := filepath.Join(dir, "deep.mod")

	for path, body := range map[string]string{
		mainMod: `module example.com/app

go 1.26

toolchain go1.26.1

require (
	example.com/direct v1.0.0
	example.com/indirect v1.0.0 // indirect
)
`,
		directMod: `module example.com/direct

go 1.22

require (
	example.com/deep v1.4.0
	example.com/pruned v0.5.0 // indirect
)
`,
		indirectMod: "module example.com/indirect\ngo 1.21\n",
		deepMod:     "module example.com/deep\ngo 1.20\n",
	} {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), []byte("example.com/direct v1.0.0 h1:test\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := fakeRunner{
		"go env GOMOD":         []byte(mainMod + "\n"),
		"go list -m -json all": []byte(fmt.Sprintf("{\"Path\":\"example.com/app\",\"Main\":true,\"GoMod\":%q,\"GoVersion\":\"1.26\"}\n{\"Path\":\"example.com/direct\",\"Version\":\"v1.0.0\",\"GoMod\":%q,\"GoVersion\":\"1.22\",\"Deprecated\":\"use example.com/new instead\"}\n{\"Path\":\"example.com/indirect\",\"Version\":\"v1.0.0\",\"GoMod\":%q,\"GoVersion\":\"1.21\"}\n{\"Path\":\"example.com/deep\",\"Version\":\"v2.0.0\",\"GoMod\":%q,\"GoVersion\":\"1.20\"}\n", mainMod, directMod, indirectMod, deepMod)),
		"go list -m -json -retracted example.com/direct@v1.0.0 example.com/indirect@v1.0.0 example.com/deep@v2.0.0": []byte("{\"Path\":\"example.com/direct\",\"Version\":\"v1.0.0\",\"Retracted\":[\"published accidentally\"]}\n{\"Path\":\"example.com/indirect\",\"Version\":\"v1.0.0\"}\n{\"Path\":\"example.com/deep\",\"Version\":\"v2.0.0\"}\n"),
		"go mod graph": []byte("example.com/app example.com/direct@v1.0.0\nexample.com/direct@v1.0.0 example.com/deep@v1.5.0\nexample.com/direct@v0.9.0 example.com/indirect@v1.0.0\nexample.com/app example.com/indirect@v1.0.0\n"),
		"go list -buildvcs=false -deps -e -json ./...":       []byte("{\"ImportPath\":\"example.com/direct/pkg\",\"Module\":{\"Path\":\"example.com/direct\",\"Version\":\"v1.0.0\"}}\n"),
		"go list -buildvcs=false -deps -test -e -json ./...": []byte("{\"ImportPath\":\"example.com/direct/pkg\",\"Module\":{\"Path\":\"example.com/direct\",\"Version\":\"v1.0.0\"}}\n{\"ImportPath\":\"example.com/indirect/testutil\",\"Module\":{\"Path\":\"example.com/indirect\",\"Version\":\"v1.0.0\"}}\n"),
		"go mod verify": []byte("all modules verified\n"),
	}
	res, err := (Loader{Runner: r}).Load(context.Background(), ".")
	if err != nil {
		t.Fatal(err)
	}
	if res.GoDirective != "1.26" || res.Toolchain != "go1.26.1" {
		t.Fatalf("go settings: directive=%q toolchain=%q", res.GoDirective, res.Toolchain)
	}
	if !res.PackageAnalysis || len(res.Packages["example.com/direct"]) != 1 || res.Packages["example.com/direct"][0] != "example.com/direct/pkg" {
		t.Fatalf("packages=%v complete=%v", res.Packages, res.PackageAnalysis)
	}
	if len(res.MainRequirements) != 2 || res.MainRequirements[0].Path != "example.com/direct" {
		t.Fatalf("main requirements=%+v", res.MainRequirements)
	}
	for _, module := range res.Modules {
		if module.Path == "example.com/indirect" && module.Scope != model.ScopeTestOnly {
			t.Fatalf("indirect scope=%s", module.Scope)
		}
	}
	got := map[string]model.DependencyKind{}
	for _, m := range res.Modules {
		got[m.Path] = m.Kind
	}
	if got["example.com/direct"] != model.DependencyDirect {
		t.Fatalf("direct=%s", got["example.com/direct"])
	}
	if got["example.com/indirect"] != model.DependencyIndirect {
		t.Fatalf("indirect=%s", got["example.com/indirect"])
	}
	if got["example.com/deep"] != model.DependencyTransitive {
		t.Fatalf("deep=%s", got["example.com/deep"])
	}
	paths := res.Graph.PathsTo("example.com/deep", 3)
	if len(paths) != 1 || len(paths[0]) != 3 || paths[0][2].Version != "v2.0.0" {
		t.Fatalf("paths=%v", paths)
	}

	var direct model.Module
	for _, module := range res.Modules {
		if module.Path == "example.com/direct" {
			direct = module
		}
	}
	if direct.GoVersion != "1.22" || direct.Deprecated != "use example.com/new instead" || !direct.ManifestAudited || len(direct.Retracted) != 1 {
		t.Fatalf("manifest metadata=%+v", direct)
	}
	if !res.Integrity.Verified || res.Integrity.MissingGoSum {
		t.Fatalf("integrity=%+v", res.Integrity)
	}
	if len(direct.Requires) != 2 {
		t.Fatalf("requirements=%+v", direct.Requires)
	}
	if direct.Requires[0].Path != "example.com/deep" || direct.Requires[0].Version != "v1.4.0" || direct.Requires[0].SelectedVersion != "v2.0.0" {
		t.Fatalf("selected requirement=%+v", direct.Requires[0])
	}
	if direct.Requires[1].Path != "example.com/pruned" || direct.Requires[1].Version != "v0.5.0" || direct.Requires[1].SelectedVersion != "" || !direct.Requires[1].Indirect {
		t.Fatalf("pruned requirement=%+v", direct.Requires[1])
	}
}

// TestParseModuleRef verifies module path and version splitting.
func TestParseModuleRef(t *testing.T) {
	got, ok := ParseModuleRef("golang.org/x/net@v0.42.0")
	if !ok || got.Path != "golang.org/x/net" || got.Version != "v0.42.0" {
		t.Fatalf("%+v %v", got, ok)
	}
}

// TestLocalReplacementIsNotScannable verifies that registry matching excludes local code.
func TestLocalReplacementIsNotScannable(t *testing.T) {
	m := model.Module{Path: "example.com/a", Version: "v1.0.0", Replace: &model.ModuleRef{Path: "../a"}, LocalReplacement: true}
	if _, _, ok := m.ScanTarget(); ok {
		t.Fatal("local replacement should be skipped")
	}
}

// TestLoadPackagesReportsErrorsWithoutModuleMetadata verifies incomplete package diagnostics.
func TestLoadPackagesReportsErrorsWithoutModuleMetadata(t *testing.T) {
	r := fakeRunner{
		"go list -buildvcs=false -deps -test -e -json ./...": []byte(`{"ImportPath":"example.com/app.test","Incomplete":true,"Error":{"Err":"test setup failed"}}`),
	}
	_, complete, warning := (Loader{Runner: r}).loadPackages(context.Background(), ".", true)
	if complete || !strings.Contains(warning, "test setup failed") {
		t.Fatalf("complete=%v warning=%q", complete, warning)
	}
}

// TestLoaderIntegrationLocalModuleGraph verifies loading against a real local replacement graph.
func TestLoaderIntegrationLocalModuleGraph(t *testing.T) {
	root := t.TempDir()
	mustWrite := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(filepath.Join(root, "go.mod"), `module example.com/app

go 1.23.0

require (
	example.com/direct v1.0.0
	example.com/deep v1.0.0 // indirect
	example.com/indirect v1.0.0 // indirect
)

replace example.com/direct => ./direct
replace example.com/indirect => ./indirect
replace example.com/deep => ./deep
replace example.com/unused => ./unused
`)
	mustWrite(filepath.Join(root, "main.go"), "package app\nimport (\n\t_ \"example.com/direct\"\n\t_ \"example.com/indirect\"\n)\n")
	mustWrite(filepath.Join(root, "direct", "go.mod"), "module example.com/direct\ngo 1.23.0\nrequire (\n\texample.com/deep v1.0.0\n\texample.com/unused v1.0.0\n)\n")
	mustWrite(filepath.Join(root, "direct", "direct.go"), "package direct\nimport _ \"example.com/deep\"\n")
	mustWrite(filepath.Join(root, "indirect", "go.mod"), "module example.com/indirect\ngo 1.23.0\n")
	mustWrite(filepath.Join(root, "indirect", "indirect.go"), "package indirect\n")
	mustWrite(filepath.Join(root, "deep", "go.mod"), "module example.com/deep\ngo 1.23.0\n")
	mustWrite(filepath.Join(root, "deep", "deep.go"), "package deep\n")
	mustWrite(filepath.Join(root, "unused", "go.mod"), "module example.com/unused\ngo 1.23.0\n")
	mustWrite(filepath.Join(root, "unused", "unused.go"), "package unused\n")

	res, err := (Loader{}).Load(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]model.DependencyKind{}
	for _, m := range res.Modules {
		kinds[m.Path] = m.Kind
	}
	if kinds["example.com/direct"] != model.DependencyDirect {
		t.Fatalf("direct=%s", kinds["example.com/direct"])
	}
	if kinds["example.com/indirect"] != model.DependencyIndirect {
		t.Fatalf("indirect=%s", kinds["example.com/indirect"])
	}
	if kinds["example.com/deep"] != model.DependencyIndirect {
		t.Fatalf("deep=%s", kinds["example.com/deep"])
	}
	if kinds["example.com/unused"] != model.DependencyTransitive {
		t.Fatalf("unused=%s", kinds["example.com/unused"])
	}
	if !res.PackageAnalysis {
		t.Fatalf("package analysis incomplete: %v", res.Warnings)
	}
	if len(res.Packages["example.com/direct"]) != 1 || len(res.Packages["example.com/deep"]) != 1 {
		t.Fatalf("loaded packages=%v", res.Packages)
	}
	if len(res.Packages["example.com/indirect"]) != 1 {
		t.Fatalf("indirect module package not loaded: %v", res.Packages["example.com/indirect"])
	}
	if len(res.Packages["example.com/unused"]) != 0 {
		t.Fatalf("graph-only module unexpectedly loaded: %v", res.Packages["example.com/unused"])
	}
	for _, module := range res.Modules {
		switch module.Path {
		case "example.com/direct", "example.com/indirect", "example.com/deep":
			if module.Scope != model.ScopeRuntime {
				t.Fatalf("scope for %s=%s", module.Path, module.Scope)
			}
		case "example.com/unused":
			if module.Scope != model.ScopeGraphOnly {
				t.Fatalf("scope for unused=%s", module.Scope)
			}
		}
	}
	paths := res.Graph.PathsTo("example.com/unused", 1)
	if len(paths) != 1 || len(paths[0]) != 3 {
		t.Fatalf("paths=%v", paths)
	}
	for _, module := range res.Modules {
		if module.Path != "example.com/direct" {
			continue
		}
		if module.GoVersion != "1.23.0" || !module.ManifestAudited || len(module.Requires) != 2 || module.Requires[0].Path != "example.com/deep" || module.Requires[1].Path != "example.com/unused" {
			t.Fatalf("manifest=%+v", module)
		}
		return
	}
	t.Fatal("direct module not found")
}
