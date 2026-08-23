package fixer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/therxwold/GoSCAn/internal/command"
	"github.com/therxwold/GoSCAn/internal/goversion"
	"github.com/therxwold/GoSCAn/internal/model"
)

// Applier applies recommended module upgrades through the Go command and rolls back failed verification.
type Applier struct{ Runner command.Runner }

// fileBackup preserves one module file so a failed remediation can be rolled back.
type fileBackup struct {
	path    string
	data    []byte
	existed bool
}

// ApplyLatest atomically upgrades loaded dependencies and Go settings to their
// newest resolved versions. Verification is performed by the narrower apply
// steps, while tests run once after the complete upgrade is assembled.
func (a Applier) ApplyLatest(ctx context.Context, root string, report *model.Report, includeVulnerabilities, runTests bool) (bool, error) {
	if a.Runner == nil {
		a.Runner = command.ExecRunner{}
	}
	backups, err := backupModuleFiles(root)
	if err != nil {
		return false, err
	}
	// ApplyLatest owns the outer transaction because its narrower Apply and
	// ApplyGo operations verify independently before the final combined test.
	rollback := func() {
		for _, backup := range backups {
			if backup.existed {
				_ = os.WriteFile(backup.path, backup.data, 0o644)
			} else {
				_ = os.Remove(backup.path)
			}
		}
	}

	applied := false
	recommendations := LatestRecommendations(report, includeVulnerabilities)
	if HasApplicable(recommendations) {
		if err := a.Apply(ctx, root, recommendations, false); err != nil {
			rollback()
			return false, err
		}
		applied = true
	}
	goApplied, err := a.ApplyGo(ctx, root, report.Go, true, true, false)
	if err != nil {
		rollback()
		return false, err
	}
	applied = applied || goApplied
	if !applied {
		return false, nil
	}
	if runTests {
		if out, err := a.Runner.Run(ctx, root, "go", "test", "./..."); err != nil {
			rollback()
			return false, fmt.Errorf("tests failed after latest upgrades; go.mod/go.sum restored: %w: %s", err, string(out))
		}
	}
	return true, nil
}

// HasApplicable reports whether findings contain at least one automatic module fix.
func HasApplicable(findings []model.Finding) bool {
	for _, f := range findings {
		if f.Fix != nil && f.Fix.To != "" && f.Module.Replace == nil {
			return true
		}
	}
	return false
}

// Apply applies deduplicated fixes, tidies the module, optionally runs tests, and restores module files on failure.
func (a Applier) Apply(ctx context.Context, root string, findings []model.Finding, runTests bool) error {
	if a.Runner == nil {
		a.Runner = command.ExecRunner{}
	}
	fixes := map[string]string{}
	for _, f := range findings {
		if f.Fix == nil || f.Fix.To == "" || f.Module.Replace != nil {
			continue
		}
		// MVS can select only one version, so retain the highest required fix when
		// several advisories affect the same module.
		fixes[f.Fix.Module] = goversion.Max(fixes[f.Fix.Module], f.Fix.To)
	}
	if len(fixes) == 0 {
		return fmt.Errorf("no automatically applicable fixes")
	}
	backups, err := backupModuleFiles(root)
	if err != nil {
		return err
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

	mods := make([]string, 0, len(fixes))
	for m := range fixes {
		mods = append(mods, m)
	}
	sort.Strings(mods)
	for _, m := range mods {
		out, err := a.Runner.Run(ctx, root, "go", "get", m+"@"+fixes[m])
		if err != nil {
			rollback()
			return fmt.Errorf("apply %s@%s: %w: %s", m, fixes[m], err, string(out))
		}
	}
	if out, err := a.Runner.Run(ctx, root, "go", "mod", "tidy"); err != nil {
		rollback()
		return fmt.Errorf("go mod tidy: %w: %s", err, string(out))
	}
	if out, err := a.Runner.Run(ctx, root, "go", "mod", "verify"); err != nil {
		rollback()
		return fmt.Errorf("go mod verify: %w: %s", err, string(out))
	}
	if runTests {
		if out, err := a.Runner.Run(ctx, root, "go", "test", "./..."); err != nil {
			rollback()
			return fmt.Errorf("tests failed; go.mod/go.sum restored: %w: %s", err, string(out))
		}
	}
	return nil
}

// backupModuleFiles captures go.mod and go.sum, including whether each file exists.
func backupModuleFiles(root string) ([]fileBackup, error) {
	var out []fileBackup
	for _, name := range []string{"go.mod", "go.sum"} {
		path := filepath.Join(root, name)
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				out = append(out, fileBackup{path: path})
				continue
			}
			return nil, err
		}
		out = append(out, fileBackup{path: path, data: data, existed: true})
	}
	return out, nil
}
