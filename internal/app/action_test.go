package app

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestActionRemediationContract verifies critical composite-action control flow.
func TestActionRemediationContract(t *testing.T) {
	data, err := os.ReadFile("../../action.yml")
	if err != nil {
		t.Fatal(err)
	}
	var action struct {
		Runs struct {
			Steps []struct {
				Name string `yaml:"name"`
				If   string `yaml:"if"`
				Run  string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(data, &action); err != nil {
		t.Fatalf("parse action.yml: %v", err)
	}
	steps := map[string]struct {
		condition string
		run       string
	}{}
	for _, step := range action.Runs.Steps {
		steps[step.Name] = struct {
			condition string
			run       string
		}{condition: step.If, run: step.Run}
		if step.Run != "" && runtime.GOOS != "windows" {
			command := exec.Command("bash", "-n")
			command.Stdin = strings.NewReader(step.Run)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("%s shell syntax: %v: %s", step.Name, err, output)
			}
		}
	}

	fix := steps["Apply configured fixes and open pull request"]
	for _, required := range []string{"github.ref_name == github.event.repository.default_branch", `args+=(--ignore "$rule")`, `fix_status`, `"$fix_status" -ne 1`} {
		if !strings.Contains(fix.condition+fix.run, required) {
			t.Fatalf("fix step is missing %q", required)
		}
	}
	scan := steps["Scan dependencies"]
	if !strings.Contains(scan.run, "validate_repo_relative") {
		t.Fatal("scan step does not enforce repository-relative path inputs")
	}
	for _, required := range []string{`--log-level "$GOSCAN_LOG_LEVEL"`, `--log-format "$GOSCAN_LOG_FORMAT"`} {
		if !strings.Contains(scan.run, required) || !strings.Contains(fix.run, required) {
			t.Fatalf("scan/fix steps do not preserve diagnostic option %q", required)
		}
	}
	enforce := steps["Enforce scan result"]
	if !strings.Contains(enforce.condition, "steps.scan.outputs.status != ''") {
		t.Fatalf("enforcement condition can mask a skipped scan: %q", enforce.condition)
	}
}
