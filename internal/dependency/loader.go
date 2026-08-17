package dependency

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/therxwold/GoSCAn/internal/command"
	"github.com/therxwold/GoSCAn/internal/model"
	"golang.org/x/mod/modfile"
)

// Loader resolves the main module, selected build list, and module graph using the Go command.
type Loader struct {
	Runner command.Runner
}

// Result contains the complete dependency information discovered for a Go module.
type Result struct {
	Root       string
	MainModule string
	Modules    []model.Module
	Graph      *Graph
}

type goListModule struct {
	Path    string        `json:"Path"`
	Version string        `json:"Version"`
	Main    bool          `json:"Main"`
	Dir     string        `json:"Dir"`
	Replace *goListModule `json:"Replace"`
}

// Load resolves every selected module and its dependency graph for dir.
func (l Loader) Load(ctx context.Context, dir string) (*Result, error) {
	if l.Runner == nil {
		l.Runner = command.ExecRunner{}
	}
	gomodOut, err := l.Runner.Run(ctx, dir, "go", "env", "GOMOD")
	if err != nil {
		return nil, fmt.Errorf("locate go.mod: %w: %s", err, strings.TrimSpace(string(gomodOut)))
	}
	gomod := strings.TrimSpace(string(gomodOut))
	if gomod == "" || gomod == "/dev/null" || strings.EqualFold(filepath.Base(gomod), "NUL") {
		return nil, errors.New("no go.mod found; run goscan inside a Go module")
	}
	root := filepath.Dir(gomod)

	mainPath, mainRequirements, err := readManifest(gomod, nil)
	if err != nil {
		return nil, fmt.Errorf("read go.mod: %w", err)
	}

	listOut, err := l.Runner.Run(ctx, root, "go", "list", "-m", "-json", "all")
	if err != nil {
		return nil, fmt.Errorf("resolve module build list: %w: %s", err, strings.TrimSpace(string(listOut)))
	}
	listed, err := decodeModuleStream(listOut)
	if err != nil {
		return nil, err
	}

	requires := make(map[string]bool, len(mainRequirements))
	for _, r := range mainRequirements {
		requires[r.Path] = r.Indirect
	}

	modules := make([]model.Module, 0, len(listed))
	selected := make(map[string]string, len(listed))
	for _, m := range listed {
		kind := model.DependencyTransitive
		explicit := false
		indirectReq := false
		if m.Main {
			kind = model.DependencyMain
			if mainPath == "" {
				mainPath = m.Path
			}
		} else if indirect, ok := requires[m.Path]; ok {
			explicit = true
			indirectReq = indirect
			kind = model.DependencyDirect
		}

		mod := model.Module{
			Path:                m.Path,
			Version:             m.Version,
			Kind:                kind,
			Main:                m.Main,
			Explicit:            explicit,
			IndirectRequirement: indirectReq,
		}
		if m.Replace != nil {
			mod.Replace = &model.ModuleRef{Path: m.Replace.Path, Version: m.Replace.Version}
			mod.LocalReplacement = m.Replace.Version == "" && m.Replace.Dir != ""
		}
		modules = append(modules, mod)
		selected[m.Path] = m.Version
	}

	graphOut, err := l.Runner.Run(ctx, root, "go", "mod", "graph")
	if err != nil {
		return nil, fmt.Errorf("read module graph: %w: %s", err, strings.TrimSpace(string(graphOut)))
	}
	graph := ParseGraph(graphOut, selected)
	graph.AddRoot(mainPath)

	return &Result{Root: root, MainModule: mainPath, Modules: modules, Graph: graph}, nil
}

func decodeModuleStream(data []byte) ([]goListModule, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	var out []goListModule
	for {
		var m goListModule
		err := dec.Decode(&m)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode module build list: %w", err)
		}
		out = append(out, m)
	}
	if len(out) == 0 {
		return nil, errors.New("go list returned an empty module build list")
	}
	return out, nil
}

type manifestRequirement struct {
	Path     string
	Version  string
	Indirect bool
}

func readManifest(path string, selected map[string]string) (string, []manifestRequirement, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	file, err := modfile.Parse(path, data, nil)
	if err != nil {
		return "", nil, err
	}
	modulePath := ""
	if file.Module != nil {
		modulePath = file.Module.Mod.Path
	}
	requirements := make([]manifestRequirement, 0, len(file.Require))
	for _, requirement := range file.Require {
		requirements = append(requirements, manifestRequirement{
			Path: requirement.Mod.Path, Version: requirement.Mod.Version, Indirect: requirement.Indirect,
		})
	}
	return modulePath, requirements, nil
}

// Graph stores module-path edges. Versions shown in paths are the MVS-selected
// versions from go list, not necessarily the lower requirement printed by
// go mod graph.
// Graph stores selected module dependency edges and can explain paths from the main module.
type Graph struct {
	adj      map[string][]string
	selected map[string]string
	roots    []string
}

// NewGraph creates an empty dependency graph using the supplied MVS-selected versions.
func NewGraph(selected map[string]string) *Graph {
	copySelected := make(map[string]string, len(selected))
	for k, v := range selected {
		copySelected[k] = v
	}
	return &Graph{adj: map[string][]string{}, selected: copySelected}
}

// ParseGraph parses go mod graph output into a selected-version dependency graph.
func ParseGraph(data []byte, selected map[string]string) *Graph {
	g := NewGraph(selected)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		parent, _ := ParseModuleRef(fields[0])
		child, _ := ParseModuleRef(fields[1])
		if parent.Path == "" || child.Path == "" {
			continue
		}
		g.adj[parent.Path] = appendUnique(g.adj[parent.Path], child.Path)
	}
	for k := range g.adj {
		sort.Strings(g.adj[k])
	}
	return g
}

// AddRoot registers a module path as a graph traversal root.
func (g *Graph) AddRoot(path string) {
	if path == "" {
		return
	}
	for _, r := range g.roots {
		if r == path {
			return
		}
	}
	g.roots = append(g.roots, path)
}

// ParseModuleRef parses a module@version reference emitted by the Go command.
func ParseModuleRef(s string) (model.ModuleRef, bool) {
	idx := strings.LastIndexByte(s, '@')
	if idx <= 0 {
		return model.ModuleRef{Path: s}, s != ""
	}
	return model.ModuleRef{Path: s[:idx], Version: s[idx+1:]}, true
}

// PathsTo returns up to limit dependency paths from registered roots to target.
func (g *Graph) PathsTo(target string, limit int) [][]model.ModuleRef {
	if target == "" || limit <= 0 {
		return nil
	}
	type item struct{ path []string }
	queue := make([]item, 0)
	for _, root := range g.roots {
		queue = append(queue, item{path: []string{root}})
	}
	var results [][]model.ModuleRef
	bestDepth := map[string]int{}
	for len(queue) > 0 && len(results) < limit {
		cur := queue[0]
		queue = queue[1:]
		node := cur.path[len(cur.path)-1]
		if node == target {
			refs := make([]model.ModuleRef, 0, len(cur.path))
			for _, p := range cur.path {
				refs = append(refs, model.ModuleRef{Path: p, Version: g.selected[p]})
			}
			results = append(results, refs)
			continue
		}
		for _, next := range g.adj[node] {
			if contains(cur.path, next) {
				continue
			}
			depth := len(cur.path)
			if d, ok := bestDepth[next]; ok && depth > d+1 {
				continue
			}
			bestDepth[next] = depth
			np := append(append([]string(nil), cur.path...), next)
			queue = append(queue, item{path: np})
		}
	}
	return results
}

func appendUnique(in []string, v string) []string {
	for _, x := range in {
		if x == v {
			return in
		}
	}
	return append(in, v)
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
