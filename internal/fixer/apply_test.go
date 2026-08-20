package fixer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/therxwold/GoSCAn/internal/model"
)

type applyRunner struct {
	failOn string
	calls  []string
	mutate bool
}

func (r *applyRunner) Run(_ context.Context, dir string, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)

	// Simulate go tooling modifying both module files. This makes rollback tests
	// prove restoration rather than merely asserting unchanged fixtures.
	if r.mutate && call == "go get example.com/a@v1.2.3" {
		_ = os.WriteFile(filepath.Join(dir, "go.mod"), []byte("mutated go.mod\n"), 0o644)
		_ = os.WriteFile(filepath.Join(dir, "go.sum"), []byte("mutated go.sum\n"), 0o644)
	}
	if r.failOn == call {
		return []byte("boom"), errors.New("exit 1")
	}
	return nil, nil
}

func writeModuleFiles(t *testing.T, root string, withSum bool) (string, string) {
	t.Helper()
	mod := "module example.com/app\n\ngo 1.23.0\n"
	sum := "example.com/original v1.0.0 h1:abc\n"
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte(mod), 0o644); err != nil {
		t.Fatal(err)
	}
	if withSum {
		if err := os.WriteFile(filepath.Join(root, "go.sum"), []byte(sum), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return mod, sum
}

func oneFix() []model.Finding {
	return []model.Finding{{
		Module: model.Module{Path: "example.com/a"},
		Fix:    &model.FixRecommendation{Module: "example.com/a", To: "v1.2.3"},
	}}
}

// Rollback tests intentionally cover both existing and newly created module files.
func TestApplySuccessRunsGetTidyAndTests(t *testing.T) {
	root := t.TempDir()
	writeModuleFiles(t, root, true)
	r := &applyRunner{}
	if err := (Applier{Runner: r}).Apply(context.Background(), root, oneFix(), true); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"go get example.com/a@v1.2.3",
		"go mod tidy",
		"go mod verify",
		"go test ./...",
	}
	if strings.Join(r.calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls=%v want=%v", r.calls, want)
	}
}

func TestApplyWithoutTestsSkipsGoTest(t *testing.T) {
	root := t.TempDir()
	writeModuleFiles(t, root, false)
	r := &applyRunner{}
	if err := (Applier{Runner: r}).Apply(context.Background(), root, oneFix(), false); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.calls, "\n")
	if strings.Contains(joined, "go test ./...") {
		t.Fatalf("unexpected test invocation: %s", joined)
	}
}

func TestApplyRollsBackBothModuleFilesOnTestFailure(t *testing.T) {
	root := t.TempDir()
	originalMod, originalSum := writeModuleFiles(t, root, true)
	r := &applyRunner{failOn: "go test ./...", mutate: true}
	if err := (Applier{Runner: r}).Apply(context.Background(), root, oneFix(), true); err == nil {
		t.Fatal("expected error")
	}
	gotMod, _ := os.ReadFile(filepath.Join(root, "go.mod"))
	gotSum, _ := os.ReadFile(filepath.Join(root, "go.sum"))
	if string(gotMod) != originalMod {
		t.Fatalf("go.mod not restored: %q", gotMod)
	}
	if string(gotSum) != originalSum {
		t.Fatalf("go.sum not restored: %q", gotSum)
	}
}

func TestApplyRemovesNewGoSumOnRollback(t *testing.T) {
	root := t.TempDir()
	originalMod, _ := writeModuleFiles(t, root, false)
	r := &applyRunner{failOn: "go test ./...", mutate: true}
	if err := (Applier{Runner: r}).Apply(context.Background(), root, oneFix(), true); err == nil {
		t.Fatal("expected error")
	}
	gotMod, _ := os.ReadFile(filepath.Join(root, "go.mod"))
	if string(gotMod) != originalMod {
		t.Fatalf("go.mod not restored: %q", gotMod)
	}
	if _, err := os.Stat(filepath.Join(root, "go.sum")); !os.IsNotExist(err) {
		t.Fatalf("go.sum should have been removed after rollback, err=%v", err)
	}
}

func TestApplyRollsBackOnGoGetFailure(t *testing.T) {
	root := t.TempDir()
	originalMod, originalSum := writeModuleFiles(t, root, true)
	r := &applyRunner{failOn: "go get example.com/a@v1.2.3", mutate: true}
	if err := (Applier{Runner: r}).Apply(context.Background(), root, oneFix(), true); err == nil {
		t.Fatal("expected error")
	}
	gotMod, _ := os.ReadFile(filepath.Join(root, "go.mod"))
	gotSum, _ := os.ReadFile(filepath.Join(root, "go.sum"))
	if string(gotMod) != originalMod || string(gotSum) != originalSum {
		t.Fatalf("module files were not restored")
	}
}

func TestApplyRollsBackOnTidyFailure(t *testing.T) {
	root := t.TempDir()
	originalMod, originalSum := writeModuleFiles(t, root, true)
	r := &applyRunner{failOn: "go mod tidy", mutate: true}
	if err := (Applier{Runner: r}).Apply(context.Background(), root, oneFix(), true); err == nil {
		t.Fatal("expected error")
	}
	gotMod, _ := os.ReadFile(filepath.Join(root, "go.mod"))
	gotSum, _ := os.ReadFile(filepath.Join(root, "go.sum"))
	if string(gotMod) != originalMod || string(gotSum) != originalSum {
		t.Fatalf("module files were not restored")
	}
}

func TestApplyRollsBackOnVerifyFailure(t *testing.T) {
	root := t.TempDir()
	originalMod, originalSum := writeModuleFiles(t, root, true)
	r := &applyRunner{failOn: "go mod verify", mutate: true}
	if err := (Applier{Runner: r}).Apply(context.Background(), root, oneFix(), true); err == nil {
		t.Fatal("expected error")
	}
	gotMod, _ := os.ReadFile(filepath.Join(root, "go.mod"))
	gotSum, _ := os.ReadFile(filepath.Join(root, "go.sum"))
	if string(gotMod) != originalMod || string(gotSum) != originalSum {
		t.Fatalf("module files were not restored")
	}
}

func TestApplyUsesHighestFixPerModule(t *testing.T) {
	root := t.TempDir()
	writeModuleFiles(t, root, false)
	r := &applyRunner{}
	fs := []model.Finding{
		{Fix: &model.FixRecommendation{Module: "m", To: "v1.2.0"}},
		{Fix: &model.FixRecommendation{Module: "m", To: "v1.3.0"}},
	}
	if err := (Applier{Runner: r}).Apply(context.Background(), root, fs, false); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.calls, "\n")
	if !strings.Contains(joined, "go get m@v1.3.0") || strings.Contains(joined, "v1.2.0") {
		t.Fatalf("calls=%s", joined)
	}
}

func TestApplySkipsReplacementFixes(t *testing.T) {
	root := t.TempDir()
	writeModuleFiles(t, root, false)
	r := &applyRunner{}
	fs := []model.Finding{{
		Module: model.Module{Path: "m", Replace: &model.ModuleRef{Path: "fork/m", Version: "v1.0.0"}},
		Fix:    &model.FixRecommendation{Module: "m", To: "v1.2.0"},
	}}
	if err := (Applier{Runner: r}).Apply(context.Background(), root, fs, false); err == nil || !strings.Contains(err.Error(), "no automatically applicable fixes") {
		t.Fatalf("err=%v", err)
	}
	if len(r.calls) != 0 {
		t.Fatalf("calls=%v", r.calls)
	}
}
