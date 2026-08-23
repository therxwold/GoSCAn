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

// applyRunner records remediation commands and injects command failures.
type applyRunner struct {
	failOn string
	calls  []string
	mutate bool
}

// Run implements command.Runner while simulating module-file mutations.
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

// writeModuleFiles creates the module files used by rollback tests.
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

// oneFix returns a representative direct dependency remediation.
func oneFix() []model.Finding {
	return []model.Finding{{
		Module: model.Module{Path: "example.com/a"},
		Fix:    &model.FixRecommendation{Module: "example.com/a", To: "v1.2.3"},
	}}
}

// TestApplySuccessRunsGetTidyAndTests verifies the complete successful command sequence.
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

// TestApplyWithoutTestsSkipsGoTest verifies the runTests switch.
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

// TestApplyRollsBackBothModuleFilesOnTestFailure verifies atomic rollback after failing tests.
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

// TestApplyRemovesNewGoSumOnRollback verifies restoration when go.sum was newly created.
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

// TestApplyRollsBackOnGoGetFailure verifies rollback after dependency upgrade failure.
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

// TestApplyRollsBackOnTidyFailure verifies rollback after go mod tidy failure.
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

// TestApplyRollsBackOnVerifyFailure verifies rollback after integrity verification failure.
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

// TestApplyUsesHighestFixPerModule verifies deduplication of fixes for one module.
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

// TestApplySkipsReplacementFixes verifies that replacement directives are not rewritten.
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

// latestReport returns dependency and Go upgrade candidates for apply tests.
func latestReport() *model.Report {
	return &model.Report{
		PackageAnalysis: true,
		Dependencies: []model.Module{{
			Path: "example.com/a", Version: "v1.0.0", Kind: model.DependencyDirect, PackagesLoaded: true,
		}},
		Health: []model.DependencyHealth{{
			Module: model.ModuleRef{Path: "example.com/a", Version: "v1.0.0"}, Outdated: true, LatestVersion: "v1.2.3",
		}},
		Go: &model.GoHealth{Directive: "1.23.0", RecommendedDirective: "1.26", DirectiveOutdated: true},
	}
}

// TestApplyLatestUpgradesDependenciesAndGoThenTestsOnce verifies latest-mode sequencing.
func TestApplyLatestUpgradesDependenciesAndGoThenTestsOnce(t *testing.T) {
	root := t.TempDir()
	writeModuleFiles(t, root, true)
	r := &applyRunner{}
	changed, err := (Applier{Runner: r}).ApplyLatest(context.Background(), root, latestReport(), true, true)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected latest upgrades")
	}
	want := []string{
		"go get example.com/a@v1.2.3",
		"go mod tidy",
		"go mod verify",
		"go mod tidy",
		"go mod verify",
		"go test ./...",
	}
	if strings.Join(r.calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls=%v want=%v", r.calls, want)
	}
}

// TestApplyLatestRollsBackEverythingOnFinalTestFailure verifies outer transaction rollback.
func TestApplyLatestRollsBackEverythingOnFinalTestFailure(t *testing.T) {
	root := t.TempDir()
	originalMod, originalSum := writeModuleFiles(t, root, true)
	r := &applyRunner{failOn: "go test ./...", mutate: true}
	if _, err := (Applier{Runner: r}).ApplyLatest(context.Background(), root, latestReport(), true, true); err == nil {
		t.Fatal("expected test failure")
	}
	gotMod, _ := os.ReadFile(filepath.Join(root, "go.mod"))
	gotSum, _ := os.ReadFile(filepath.Join(root, "go.sum"))
	if string(gotMod) != originalMod || string(gotSum) != originalSum {
		t.Fatalf("latest upgrade was not rolled back: go.mod=%q go.sum=%q", gotMod, gotSum)
	}
}
