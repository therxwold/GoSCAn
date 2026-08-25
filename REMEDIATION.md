# Remediation

GoSCAn separates remediation planning from mutation. Running `fix` without
`--apply` never intentionally modifies the target module.

## Minimum-safe planning

Show recommendations based on each finding's first fixed version:

```bash
goscan fix
```

For a direct dependency, the plan recommends upgrading the existing direct
requirement. For a vulnerable transitive dependency, it recommends an explicit
indirect requirement:

```text
require golang.org/x/net v0.25.0 // indirect
```

The transitive pin raises the minimum selected version across the graph through
Go MVS. It is deterministic and directly addresses the vulnerable selection.
GoSCAn does not currently search for a parent-module upgrade that happens to
raise the transitive version.

When multiple findings affect the same module, the plan chooses the highest
required fixed version.

## Applying minimum-safe fixes

```bash
goscan fix --apply
```

Only findings with an automatically applicable fixed version are changed.
Ignored findings and replacement directives are excluded.

The apply sequence is:

1. Record the original existence and contents of `go.mod` and `go.sum`.
2. Run sorted, deduplicated `go get module@first-fixed` operations.
3. Run `go mod tidy`.
4. Run `go mod verify`.
5. Run `go test ./...` when enabled.
6. Rescan the module using the same material scan settings.
7. Report selected-version changes and resolved or newly introduced findings.

Disable tests explicitly when required:

```bash
goscan fix --apply --test=false
```

Skipping tests reduces verification and should be visible in the review process.

## Newest-version planning

Preview the newest eligible versions resolved by the Go command:

```bash
goscan fix --latest
```

The plan can include:

- loaded direct, indirect, and transitive dependencies with newer versions;
- vulnerable modules when vulnerability remediation is enabled;
- the main `go` directive;
- an existing `toolchain` directive.

Apply the plan with:

```bash
goscan fix --apply --latest
```

Latest mode is deliberately different from minimum-safe mode. It chooses the
newest resolved release rather than the smallest version known to close an
affected range.

Graph-only modules are left to their loaded parents when package analysis
completed. This avoids filling the root `go.mod` with direct pins for tooling or
otherwise unloaded graph entries. Replacement directives remain excluded.

## Selecting remediation categories

The configuration defaults are:

```yaml
fix:
  run_tests: true
  vulnerabilities: true
  upgrade_go: false
  upgrade_toolchain: false
  timeout: "5m"
```

CLI category flags include:

```bash
goscan fix --apply --vulnerabilities=true
goscan fix --apply --upgrade-go=true
goscan fix --apply --upgrade-toolchain=true
```

`--upgrade-toolchain` changes only an existing `toolchain` directive. It does not
introduce one into a module that does not already use it.

Maintenance findings such as an abandoned library are never replaced
automatically. Choosing a successor library is an architectural decision rather
than a safe version edit.

## Replacement safety

GoSCAn never automatically rewrites a `replace` directive.

- A local replacement has no registry version that accurately identifies its
  code and is not eligible for registry advisory remediation.
- A versioned replacement is scanned using its replacement target, but changing
  either side of the directive requires explicit human intent.

## Before/after report

After a successful apply, GoSCAn rescans and attaches an `upgrade_result` to JSON
output. It records:

- modules or Go settings added, removed, or changed;
- vulnerabilities resolved by the upgrade;
- vulnerabilities newly introduced after selection changed.

Terminal output renders the same decision-relevant summary. Findings that remain
active are present in the normal finding list. An applied fix can therefore be
useful while still returning exit status `1` because another finding remains.

## Rollback guarantees

When an ordinary `go get`, tidy, verification, or test operation returns an
error, GoSCAn restores:

- the original contents of `go.mod` and `go.sum` when they existed;
- absence of either file when it did not exist before the operation.

Rollback is not a filesystem transaction. It cannot guarantee recovery after:

- process termination or machine failure;
- disk or filesystem corruption;
- concurrent edits by another process;
- repository-controlled tests modifying unrelated files;
- signals or failures that prevent cleanup code from running.

Use a clean checkout, disposable CI worker, or temporary worktree as the
operational recovery boundary.

## Trust and execution warning

Apply mode invokes Go tooling in the target repository. `go test ./...` can
execute repository-controlled code, and Go commands can download modules or
toolchains according to the environment.

Run remediation only when:

- the repository and branch are trusted;
- CI credentials use least privilege;
- the worker is disposable or isolated;
- the proposed `go.mod` and `go.sum` changes will be reviewed;
- the before/after report and tests are retained.

## Automatic GitHub pull requests

The composite Action can apply selected categories and open or refresh a pull
request. Relevant inputs are:

```yaml
with:
  create-pr: "true"
  pr-vulnerabilities: "true"
  pr-go-version: "true"
  pr-toolchain: "true"
  pr-branch: goscan/updates
```

Automatic PR generation:

- runs only outside pull-request events and from the repository default branch;
- propagates source, strict-enrichment, health, and ignore settings into fix and
  rescan behavior;
- accepts exit status `1` so a partial fix can still become a reviewable PR;
- commits only the target module's `go.mod` and existing/new `go.sum`;
- still enforces the original scan status after attempting remediation.

The calling workflow must provide `contents:write` and `pull-requests:write` for
the remediation job. See [CI integration](CI.md) for complete examples.
