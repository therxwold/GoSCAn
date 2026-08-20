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

type fakeRunner map[string][]byte

func (f fakeRunner) Run(_ context.Context, _ string, name string, args ...string) ([]byte, error) {
	key := name + " " + strings.Join(args, " ")
	v, ok := f[key]
	if !ok {
		return nil, fmt.Errorf("unexpected command %s", key)
	}
	return v, nil
}

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

	r := fakeRunner{
		"go env GOMOD":         []byte(mainMod + "\n"),
		"go list -m -json all": []byte(fmt.Sprintf("{\"Path\":\"example.com/app\",\"Main\":true,\"GoMod\":%q,\"GoVersion\":\"1.26\"}\n{\"Path\":\"example.com/direct\",\"Version\":\"v1.0.0\",\"GoMod\":%q,\"GoVersion\":\"1.22\",\"Deprecated\":\"use example.com/new instead\"}\n{\"Path\":\"example.com/indirect\",\"Version\":\"v1.0.0\",\"GoMod\":%q,\"GoVersion\":\"1.21\"}\n{\"Path\":\"example.com/deep\",\"Version\":\"v2.0.0\",\"GoMod\":%q,\"GoVersion\":\"1.20\"}\n", mainMod, directMod, indirectMod, deepMod)),
		"go mod graph":         []byte("example.com/app example.com/direct@v1.0.0\nexample.com/direct@v1.0.0 example.com/deep@v1.5.0\nexample.com/direct@v0.9.0 example.com/indirect@v1.0.0\nexample.com/app example.com/indirect@v1.0.0\n"),
	}
	res, err := (Loader{Runner: r}).Load(context.Background(), ".")
	if err != nil {
		t.Fatal(err)
	}
	if res.GoDirective != "1.26" || res.Toolchain != "go1.26.1" {
		t.Fatalf("go settings: directive=%q toolchain=%q", res.GoDirective, res.Toolchain)
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
	if direct.GoVersion != "1.22" || direct.Deprecated != "use example.com/new instead" || !direct.ManifestAudited {
		t.Fatalf("manifest metadata=%+v", direct)
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

func TestParseModuleRef(t *testing.T) {
	got, ok := ParseModuleRef("golang.org/x/net@v0.42.0")
	if !ok || got.Path != "golang.org/x/net" || got.Version != "v0.42.0" {
		t.Fatalf("%+v %v", got, ok)
	}
}

func TestLocalReplacementIsNotScannable(t *testing.T) {
	m := model.Module{Path: "example.com/a", Version: "v1.0.0", Replace: &model.ModuleRef{Path: "../a"}, LocalReplacement: true}
	if _, _, ok := m.ScanTarget(); ok {
		t.Fatal("local replacement should be skipped")
	}
}

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
	example.com/indirect v1.0.0 // indirect
)

replace example.com/direct => ./direct
replace example.com/indirect => ./indirect
replace example.com/deep => ./deep
`)
	mustWrite(filepath.Join(root, "main.go"), "package app\nimport _ \"example.com/direct\"\n")
	mustWrite(filepath.Join(root, "direct", "go.mod"), "module example.com/direct\ngo 1.23.0\nrequire example.com/deep v1.0.0\n")
	mustWrite(filepath.Join(root, "direct", "direct.go"), "package direct\nimport _ \"example.com/deep\"\n")
	mustWrite(filepath.Join(root, "indirect", "go.mod"), "module example.com/indirect\ngo 1.23.0\n")
	mustWrite(filepath.Join(root, "indirect", "indirect.go"), "package indirect\n")
	mustWrite(filepath.Join(root, "deep", "go.mod"), "module example.com/deep\ngo 1.23.0\n")
	mustWrite(filepath.Join(root, "deep", "deep.go"), "package deep\n")

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
	if kinds["example.com/deep"] != model.DependencyTransitive {
		t.Fatalf("deep=%s", kinds["example.com/deep"])
	}
	paths := res.Graph.PathsTo("example.com/deep", 1)
	if len(paths) != 1 || len(paths[0]) != 3 {
		t.Fatalf("paths=%v", paths)
	}
	for _, module := range res.Modules {
		if module.Path != "example.com/direct" {
			continue
		}
		if module.GoVersion != "1.23.0" || !module.ManifestAudited || len(module.Requires) != 1 || module.Requires[0].Path != "example.com/deep" {
			t.Fatalf("manifest=%+v", module)
		}
		return
	}
	t.Fatal("direct module not found")
}
