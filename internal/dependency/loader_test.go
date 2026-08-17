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
	if err := os.WriteFile(mainMod, []byte(`module example.com/app

require (
	example.com/direct v1.0.0
	example.com/indirect v1.0.0 // indirect
)
`), 0o644); err != nil {
		t.Fatal(err)
	}
	r := fakeRunner{
		"go env GOMOD":         []byte(mainMod + "\n"),
		"go list -m -json all": []byte("{\"Path\":\"example.com/app\",\"Main\":true}\n{\"Path\":\"example.com/direct\",\"Version\":\"v1.0.0\"}\n{\"Path\":\"example.com/indirect\",\"Version\":\"v1.0.0\"}\n{\"Path\":\"example.com/deep\",\"Version\":\"v2.0.0\"}\n"),
		"go mod graph":         []byte("example.com/app example.com/direct@v1.0.0\nexample.com/direct@v1.0.0 example.com/deep@v2.0.0\nexample.com/app example.com/indirect@v1.0.0\n"),
	}
	res, err := (Loader{Runner: r}).Load(context.Background(), ".")
	if err != nil {
		t.Fatal(err)
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
	if len(paths) != 1 || len(paths[0]) != 3 {
		t.Fatalf("paths=%v", paths)
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
}
