package versionresolver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/therxwold/GoSCAn/internal/command"
)

// Resolver asks the Go command for module version information.
type Resolver struct{ Runner command.Runner }

// Latest resolves the latest available version of modulePath.
func (r Resolver) Latest(ctx context.Context, dir, modulePath string) (string, error) {
	if r.Runner == nil {
		r.Runner = command.ExecRunner{}
	}
	out, err := r.Runner.Run(ctx, dir, "go", "list", "-m", "-json", modulePath+"@latest")
	if err != nil {
		return "", fmt.Errorf("resolve latest %s: %w: %s", modulePath, err, strings.TrimSpace(string(out)))
	}
	var m struct {
		Version string `json:"Version"`
	}
	if err := json.Unmarshal(out, &m); err != nil {
		return "", fmt.Errorf("decode latest %s: %w", modulePath, err)
	}
	return m.Version, nil
}
