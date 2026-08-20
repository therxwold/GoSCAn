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

type fileBackup struct {
	path    string
	data    []byte
	existed bool
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
