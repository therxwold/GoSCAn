package dependency

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
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
	// MainRequirements are the requirements declared by the main module. They
	// are kept separately because Modules also contains dependency manifests.
	MainRequirements []model.ModuleRequirement
	GoDirective      string
	Toolchain        string
	Modules          []model.Module
	Graph            *Graph
	// Packages maps module paths to package import paths loaded by `go list` for
	// the main module and its tests. PackageAnalysis is false when that analysis
	// could not be completed, in which case callers must remain conservative.
	Packages        map[string][]string
	RuntimePackages map[string][]string
	TestPackages    map[string][]string
	PackageAnalysis bool
	Integrity       model.Integrity
	Warnings        []string
}

// goListModule models the subset of `go list -m -json` output used by the loader.
type goListModule struct {
	Path       string        `json:"Path"`
	Version    string        `json:"Version"`
	Main       bool          `json:"Main"`
	Dir        string        `json:"Dir"`
	GoMod      string        `json:"GoMod"`
	GoVersion  string        `json:"GoVersion"`
	Deprecated string        `json:"Deprecated"`
	Retracted  []string      `json:"Retracted"`
	Replace    *goListModule `json:"Replace"`
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
	goDirective, toolchain, err := readGoSettings(gomod)
	if err != nil {
		return nil, fmt.Errorf("read go.mod Go settings: %w", err)
	}

	listOut, err := l.Runner.Run(ctx, root, "go", "list", "-m", "-json", "all")
	if err != nil {
		return nil, fmt.Errorf("resolve module build list: %w: %s", err, strings.TrimSpace(string(listOut)))
	}
	listed, err := decodeModuleStream(listOut)
	if err != nil {
		return nil, err
	}
	// Retractions are queried separately by exact version. Adding -retracted to
	// the build-list command can make Go demand go.sum changes during a scan.
	retractionWarning := l.loadRetractions(ctx, root, listed)

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
			if indirect {
				kind = model.DependencyIndirect
			} else {
				kind = model.DependencyDirect
			}
		}

		mod := model.Module{
			Path:                m.Path,
			Version:             m.Version,
			Kind:                kind,
			Main:                m.Main,
			Explicit:            explicit,
			IndirectRequirement: indirectReq,
			GoVersion:           m.GoVersion,
			Deprecated:          m.Deprecated,
			Retracted:           append([]string(nil), m.Retracted...),
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

	// The difference between these two package sets identifies dependencies that
	// are reachable only from tests.
	runtimePackages, runtimeOK, runtimeWarning := l.loadPackages(ctx, root, false)
	testPackages, testOK, testWarning := l.loadPackages(ctx, root, true)
	packages := mergePackages(runtimePackages, testPackages)
	packageAnalysis := runtimeOK && testOK
	packageWarning := strings.Join(nonEmpty(runtimeWarning, testWarning), "; ")
	integrity := l.verifyIntegrity(ctx, root, len(listed) > 1)

	_, mainRequirements, err = readManifest(gomod, selected)
	if err != nil {
		return nil, fmt.Errorf("read go.mod requirements: %w", err)
	}
	manifestRequirements := map[string][]model.ModuleRequirement{
		mainPath: mainRequirements,
	}
	manifestAudited := map[string]bool{mainPath: true}
	var warnings []string
	if retractionWarning != "" {
		warnings = append(warnings, retractionWarning)
	}
	if packageWarning != "" {
		warnings = append(warnings, packageWarning)
	}
	for _, listedModule := range listed {
		if listedModule.Main || listedModule.GoMod == "" {
			continue
		}
		_, requirements, err := readManifest(listedModule.GoMod, selected)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("inspect %s@%s go.mod: %v", listedModule.Path, listedModule.Version, err))
			continue
		}
		manifestRequirements[listedModule.Path] = requirements
		manifestAudited[listedModule.Path] = true
	}
	for i := range modules {
		reqs, ok := manifestRequirements[modules[i].Path]
		if !ok {
			reqs = graph.RequirementsFrom(modules[i].Path)
		}
		modules[i].Requires = reqs
		modules[i].ManifestAudited = manifestAudited[modules[i].Path]
		modules[i].PackagesLoaded = len(packages[modules[i].Path]) > 0
		switch {
		case len(runtimePackages[modules[i].Path]) > 0:
			modules[i].Scope = model.ScopeRuntime
		case len(testPackages[modules[i].Path]) > 0:
			modules[i].Scope = model.ScopeTestOnly
		default:
			modules[i].Scope = model.ScopeGraphOnly
		}
	}

	return &Result{
		Root: root, MainModule: mainPath, MainRequirements: mainRequirements,
		GoDirective: goDirective, Toolchain: toolchain, Modules: modules, Graph: graph,
		Packages: packages, RuntimePackages: runtimePackages, TestPackages: testPackages,
		PackageAnalysis: packageAnalysis, Integrity: integrity, Warnings: warnings,
	}, nil
}

// loadRetractions enriches selected modules with exact-version retraction reasons.
func (l Loader) loadRetractions(ctx context.Context, root string, listed []goListModule) string {
	const chunkSize = 100
	type selectedModule struct {
		index int
		key   string
	}
	var selected []selectedModule
	for i, module := range listed {
		if module.Main || module.Version == "" || (module.Replace != nil && module.Replace.Version == "") {
			continue
		}
		path, version := module.Path, module.Version
		if module.Replace != nil && module.Replace.Path != "" && module.Replace.Version != "" {
			path, version = module.Replace.Path, module.Replace.Version
		}
		selected = append(selected, selectedModule{index: i, key: path + "@" + version})
	}
	for start := 0; start < len(selected); start += chunkSize {
		// Chunking bounds command-line size for applications with large module graphs.
		end := min(start+chunkSize, len(selected))
		args := []string{"list", "-m", "-json", "-retracted"}
		for _, module := range selected[start:end] {
			args = append(args, module.key)
		}
		out, err := l.Runner.Run(ctx, root, "go", args...)
		if err != nil {
			return fmt.Sprintf("retraction metadata unavailable: %v: %s", err, strings.TrimSpace(string(out)))
		}
		records, err := decodeModuleStream(out)
		if err != nil {
			return "retraction metadata unavailable: " + err.Error()
		}
		byKey := make(map[string][]string, len(records))
		for _, record := range records {
			byKey[record.Path+"@"+record.Version] = record.Retracted
		}
		for _, module := range selected[start:end] {
			listed[module.index].Retracted = append([]string(nil), byKey[module.key]...)
		}
	}
	return ""
}

// goListPackage models package ownership and load errors from `go list -json`.
type goListPackage struct {
	ImportPath string        `json:"ImportPath"`
	Module     *goListModule `json:"Module"`
	Incomplete bool          `json:"Incomplete"`
	Error      *struct {
		Err string `json:"Err"`
	} `json:"Error"`
}

// loadPackages maps selected modules to imported packages for production or test builds.
func (l Loader) loadPackages(ctx context.Context, root string, includeTests bool) (map[string][]string, bool, string) {
	args := []string{"list", "-buildvcs=false", "-deps"}
	if includeTests {
		args = append(args, "-test")
	}
	args = append(args, "-e", "-json", "./...")
	out, err := l.Runner.Run(ctx, root, "go", args...)
	if err != nil {
		return nil, false, fmt.Sprintf("resolve imported packages: %v: %s", err, strings.TrimSpace(string(out)))
	}
	dec := json.NewDecoder(bytes.NewReader(out))
	packages := map[string][]string{}
	complete := true
	var packageErrors []string
	for {
		var pkg goListPackage
		err := dec.Decode(&pkg)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, false, fmt.Sprintf("decode imported packages: %v", err)
		}
		if pkg.Incomplete || pkg.Error != nil {
			complete = false
			if pkg.Error != nil && pkg.Error.Err != "" {
				packageErrors = append(packageErrors, pkg.Error.Err)
			}
		}
		if pkg.Module == nil || pkg.Module.Path == "" || pkg.ImportPath == "" {
			continue
		}
		packages[pkg.Module.Path] = appendUnique(packages[pkg.Module.Path], pkg.ImportPath)
	}
	for module := range packages {
		sort.Strings(packages[module])
	}
	if !complete {
		detail := strings.Join(uniqueSortedStrings(packageErrors), "; ")
		if detail != "" {
			return packages, false, "imported package analysis incomplete: " + detail
		}
		return packages, false, "imported package analysis incomplete"
	}
	return packages, true, ""
}

// mergePackages returns the sorted union of package maps grouped by module path.
func mergePackages(groups ...map[string][]string) map[string][]string {
	out := map[string][]string{}
	for _, group := range groups {
		for module, packages := range group {
			for _, pkg := range packages {
				out[module] = appendUnique(out[module], pkg)
			}
			sort.Strings(out[module])
		}
	}
	return out
}

// nonEmpty filters empty strings while retaining the input order.
func nonEmpty(values ...string) []string {
	var out []string
	for _, value := range values {
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

// verifyIntegrity records go.sum presence and the result of `go mod verify`.
func (l Loader) verifyIntegrity(ctx context.Context, root string, hasDependencies bool) model.Integrity {
	integrity := model.Integrity{}
	if hasDependencies {
		if _, err := os.Stat(filepath.Join(root, "go.sum")); os.IsNotExist(err) {
			integrity.MissingGoSum = true
		}
	}
	out, err := l.Runner.Run(ctx, root, "go", "mod", "verify")
	if err != nil {
		integrity.Error = strings.TrimSpace(string(out))
		if integrity.Error == "" {
			integrity.Error = err.Error()
		}
		return integrity
	}
	integrity.Verified = true
	return integrity
}

// uniqueSortedStrings removes duplicate strings and sorts the result.
func uniqueSortedStrings(values []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// readGoSettings extracts go and toolchain directives from a go.mod file.
func readGoSettings(path string) (goDirective, toolchain string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}
	file, err := modfile.Parse(path, data, nil)
	if err != nil {
		return "", "", err
	}
	if file.Go != nil {
		goDirective = file.Go.Version
	}
	if file.Toolchain != nil {
		toolchain = file.Toolchain.Name
	}
	return goDirective, toolchain, nil
}

// decodeModuleStream decodes the concatenated JSON objects emitted by `go list`.
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

// readManifest parses one go.mod and annotates requirements with MVS-selected versions.
func readManifest(path string, selected map[string]string) (string, []model.ModuleRequirement, error) {
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
	requirements := make([]model.ModuleRequirement, 0, len(file.Require))
	for _, requirement := range file.Require {
		requirements = append(requirements, model.ModuleRequirement{
			Path:            requirement.Mod.Path,
			Version:         requirement.Mod.Version,
			SelectedVersion: selected[requirement.Mod.Path],
			Indirect:        requirement.Indirect,
		})
	}
	sort.Slice(requirements, func(i, j int) bool {
		if requirements[i].Path != requirements[j].Path {
			return requirements[i].Path < requirements[j].Path
		}
		return requirements[i].Version < requirements[j].Version
	})
	return modulePath, requirements, nil
}

// Graph stores selected module dependency edges and manifest requirements.
// Versions shown in paths are the MVS-selected versions from go list, while
// ModuleRequirement keeps the lower version a selected parent may have declared.
type Graph struct {
	adj          map[string][]string
	requirements map[string][]model.ModuleRequirement
	selected     map[string]string
	roots        []string
}

// NewGraph creates an empty dependency graph using the supplied MVS-selected versions.
func NewGraph(selected map[string]string) *Graph {
	copySelected := make(map[string]string, len(selected))
	maps.Copy(copySelected, selected)
	return &Graph{adj: map[string][]string{}, requirements: map[string][]model.ModuleRequirement{}, selected: copySelected}
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
		selectedParent, ok := selected[parent.Path]
		if !ok || selectedParent != parent.Version {
			// go mod graph can contain requirements from versions that lost MVS.
			// They are useful historical graph nodes, but they do not describe the
			// go.mod of the selected parent and must not create active paths.
			continue
		}
		selectedChild, childSelected := selected[child.Path]
		if !childSelected {
			continue
		}
		g.adj[parent.Path] = appendUnique(g.adj[parent.Path], child.Path)
		g.requirements[parent.Path] = appendRequirement(g.requirements[parent.Path], model.ModuleRequirement{
			Path: child.Path, Version: child.Version, SelectedVersion: selectedChild,
		})
	}
	for k := range g.adj {
		sort.Strings(g.adj[k])
	}
	for k := range g.requirements {
		sort.Slice(g.requirements[k], func(i, j int) bool {
			if g.requirements[k][i].Path != g.requirements[k][j].Path {
				return g.requirements[k][i].Path < g.requirements[k][j].Path
			}
			return g.requirements[k][i].Version < g.requirements[k][j].Version
		})
	}
	return g
}

// RequirementsFrom returns requirements declared by the selected version of parent.
// The requested version comes from the dependency manifest while SelectedVersion
// records the version that won Go's module version selection.
func (g *Graph) RequirementsFrom(parent string) []model.ModuleRequirement {
	reqs := g.requirements[parent]
	return append([]model.ModuleRequirement(nil), reqs...)
}

// AddRoot registers a module path as a graph traversal root.
func (g *Graph) AddRoot(path string) {
	if path == "" {
		return
	}
	if slices.Contains(g.roots, path) {
		return
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

// appendRequirement adds v unless an equivalent requirement already exists.
func appendRequirement(in []model.ModuleRequirement, v model.ModuleRequirement) []model.ModuleRequirement {
	for _, existing := range in {
		if existing.Path == v.Path && existing.Version == v.Version && existing.SelectedVersion == v.SelectedVersion {
			return in
		}
	}
	return append(in, v)
}

// appendUnique adds v only when it is not already present.
func appendUnique(in []string, v string) []string {
	if slices.Contains(in, v) {
		return in
	}
	return append(in, v)
}

// contains reports whether xs contains v.
func contains(xs []string, v string) bool {
	return slices.Contains(xs, v)
}
