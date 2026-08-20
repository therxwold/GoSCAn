package fixer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/therxwold/GoSCAn/internal/command"
	"github.com/therxwold/GoSCAn/internal/model"
	"golang.org/x/mod/modfile"
)

// ApplyGo upgrades the main module's go directive and/or existing toolchain directive,
// then verifies the module and rolls back go.mod/go.sum if verification fails.
func (a Applier) ApplyGo(ctx context.Context, root string, health *model.GoHealth, upgradeDirective, upgradeToolchain, runTests bool) (bool, error) {
	if health == nil {
		return false, nil
	}
	changeGo := upgradeDirective && health.DirectiveOutdated && health.RecommendedDirective != ""
	changeToolchain := upgradeToolchain && health.ToolchainUpgradeEligible && health.ToolchainOutdated && health.RecommendedToolchain != ""
	if !changeGo && !changeToolchain {
		return false, nil
	}
	if a.Runner == nil {
		a.Runner = command.ExecRunner{}
	}
	backups, err := backupModuleFiles(root)
	if err != nil {
		return false, err
	}
	rollback := func() {
		for _, b := range backups {
			if b.existed {
				_ = os.WriteFile(b.path, b.data, 0o644)
			} else {
				_ = os.Remove(b.path)
			}
		}
	}

	goModPath := filepath.Join(root, "go.mod")
	data, err := os.ReadFile(goModPath)
	if err != nil {
		return false, err
	}
	file, err := modfile.Parse(goModPath, data, nil)
	if err != nil {
		return false, fmt.Errorf("parse go.mod: %w", err)
	}
	if changeGo {
		if err := file.AddGoStmt(health.RecommendedDirective); err != nil {
			return false, fmt.Errorf("set go directive: %w", err)
		}
	}
	if changeToolchain {
		if err := file.AddToolchainStmt(health.RecommendedToolchain); err != nil {
			return false, fmt.Errorf("set toolchain directive: %w", err)
		}
	}
	formatted, err := file.Format()
	if err != nil {
		return false, fmt.Errorf("format go.mod: %w", err)
	}
	if err := os.WriteFile(goModPath, formatted, 0o644); err != nil {
		rollback()
		return false, err
	}
	if out, err := a.Runner.Run(ctx, root, "go", "mod", "tidy"); err != nil {
		rollback()
		return false, fmt.Errorf("go mod tidy after Go upgrade: %w: %s", err, string(out))
	}
	if out, err := a.Runner.Run(ctx, root, "go", "mod", "verify"); err != nil {
		rollback()
		return false, fmt.Errorf("go mod verify after Go upgrade: %w: %s", err, string(out))
	}
	if runTests {
		if out, err := a.Runner.Run(ctx, root, "go", "test", "./..."); err != nil {
			rollback()
			return false, fmt.Errorf("tests failed after Go upgrade; go.mod/go.sum restored: %w: %s", err, string(out))
		}
	}
	return true, nil
}
