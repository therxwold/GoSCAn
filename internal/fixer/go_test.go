package fixer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/therxwold/GoSCAn/internal/model"
)

func TestApplyGoUpgradesDirectiveAndExistingToolchain(t *testing.T) {
	root := t.TempDir()
	original := "module example.com/app\n\ngo 1.18\n\ntoolchain go1.25.1\n"
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &applyRunner{}
	health := &model.GoHealth{
		Directive: "1.18", Toolchain: "go1.25.1", RecommendedDirective: "1.26", RecommendedToolchain: "go1.26.6",
		DirectiveOutdated: true, ToolchainOutdated: true, ToolchainUpgradeEligible: true,
	}
	changed, err := (Applier{Runner: r}).ApplyGo(context.Background(), root, health, true, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected Go settings to change")
	}
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	if !strings.Contains(got, "go 1.26") || !strings.Contains(got, "toolchain go1.26.6") {
		t.Fatalf("go.mod=%s", got)
	}
	wantCalls := "go mod tidy\ngo mod verify\ngo test ./..."
	if strings.Join(r.calls, "\n") != wantCalls {
		t.Fatalf("calls=%v", r.calls)
	}
}

func TestApplyGoDoesNotAddMissingToolchain(t *testing.T) {
	root := t.TempDir()
	original := "module example.com/app\n\ngo 1.18\n"
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &applyRunner{}
	health := &model.GoHealth{Directive: "1.18", RecommendedDirective: "1.26", RecommendedToolchain: "go1.26.6", DirectiveOutdated: true}
	changed, err := (Applier{Runner: r}).ApplyGo(context.Background(), root, health, true, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected go directive change")
	}
	data, _ := os.ReadFile(filepath.Join(root, "go.mod"))
	if strings.Contains(string(data), "toolchain") {
		t.Fatalf("missing toolchain should not be added: %s", data)
	}
}

func TestApplyGoRollsBackOnVerificationFailure(t *testing.T) {
	root := t.TempDir()
	original := "module example.com/app\n\ngo 1.18\n"
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &applyRunner{failOn: "go mod verify"}
	health := &model.GoHealth{Directive: "1.18", RecommendedDirective: "1.26", DirectiveOutdated: true}
	if _, err := (Applier{Runner: r}).ApplyGo(context.Background(), root, health, true, false, false); err == nil {
		t.Fatal("expected verification failure")
	}
	data, _ := os.ReadFile(filepath.Join(root, "go.mod"))
	if string(data) != original {
		t.Fatalf("go.mod was not restored: %s", data)
	}
}
