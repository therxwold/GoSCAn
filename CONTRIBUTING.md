# CONTRIBUTING // GoSCAn

> A contribution crosses a trust boundary.
>
> GoSCAn helps decide whether a Go module graph is safe to ship. A small change
> can alter what the scanner reports, what it considers reachable, what it
> proposes to upgrade, or whether a fix is deemed safe. Make the intent visible.
> Leave evidence. Fail closed.

GoSCAn is part of PROJECT ÞERXWOLD: a research archive built where human
 direction, AI systems, security, and code begin to answer back.

Contributions are welcome. Careless ambiguity is not.

---

## 00 // BEFORE YOU CROSS

Before opening an issue or pull request:

- Search the existing issues and pull requests.
- Keep one problem or logical change per submission.
- Open an issue before implementing a large feature, public CLI contract change,
  new report type, new database provider, or change to security semantics.
- Do not publish credentials, private module metadata, personal data,
  unreleased vulnerability details, or other secrets.
- Assume that invalid, incomplete, or ambiguous behavior must fail closed.

// The threshold is open. The trust boundary still matters.

---

## 01 // WRITING ISSUES

An issue should give another person enough signal to understand the problem
without reconstructing your environment or guessing what you meant.

### Issue titles

Use:

```text
<scope>: <specific summary>
```

Use the affected component or concern as the scope. Common scopes include
`scan`, `fix`, `db`, `report`, `ci`, `deps`, `govulncheck`, `osv`, `docs`,
`remediation`, `output`, `config`, and `performance`.

Examples:

```text
scan: fail on high severity when loaded packages are reachable
fix: prefer minimal safe upgrades over newest version
db: local cache ignores retracted module versions
```

Avoid titles such as `bug`, `broken`, `does not work`, or `please add support`.

### Bug reports

A bug report should contain:

- **Signal** — a concise description of the failure.
- **Impact** — why it matters, especially whether it may incorrectly allow,
  deny, under-report, misclassify, or overstate a dependency vulnerability.
- **System Info** — GoSCAn version or commit, Go version, operating system, and
  relevant integration details.
- **Reproduction** — the smallest module, command, or scan invocation that
  demonstrates the problem.
- **Observed behavior** — what happened, including complete diagnostics or
  report output.
- **Expected behavior** — what should have happened and why.
- **Relevant code** — affected packages, files, functions, or commands when
  known.
- **Possible direction** — optional; describe an outcome, not a demand for one
  implementation.
- **AI assistance** — disclose whether AI was used to prepare the report.

Use this template:

```markdown
## Signal

## Impact

## System Info

- GoSCAn version or commit:
- Go version:
- Operating system:
- Integration or runtime:

## Reproduction

## Observed behavior

## Expected behavior

## Relevant code

## Possible direction

## AI assistance

Was AI used to prepare this issue?

- [ ] No
- [ ] Yes

If yes:

- Tool or provider:
- Model:
- Used for:
- Human verification performed:
```

### Feature requests

Start with the problem, not the implementation you already decided to build.

Include the use case, current limitation, desired behavior, alternatives you
considered, compatibility impact, and security implications. For scanner,
reporting, remediation, or database changes, explain the expected effects on
module selection, output contracts, baselines, exceptions, reachability
analysis, and existing workflows.

Feature requests must answer the same **AI assistance** question used by bug
reports.

### Performance reports

Include a reproducible benchmark or profile when possible. State module size,
workload, scan command, Go version, and measurements. Performance changes must
not weaken correctness, evidence quality, or fail-closed behavior.

### Security reports

Do not open a public issue containing exploit details, real secrets, or an
uncoordinated vulnerability report. Use GitHub private vulnerability reporting
when available, or contact the maintainers privately.

---

## 02 // PREPARE THE WORKTREE

GoSCAn uses the Go version declared in `go.mod` and the toolchain specified by
that module.

```sh
git clone https://github.com/therxwold/GoSCAn.git
cd GoSCAn
go test ./...
```

Before submitting a pull request, run the checks used by CI:

```sh
make check
make test-race
make vet
make build
```

For the full release-quality verification used by the project:

```sh
make release-check
```

When changing scanner behavior, remediation logic, output formatting, or
security evidence paths, also run the relevant command-level checks:

```sh
goscan scan ./path/to/module
 goscan fix --apply --dry-run ./path/to/module
```

If you change Go code or semantics that affect the binary, rebuild and run the
project's local validation path before opening a PR.

---

## 03 // COMMIT PROTOCOL

Every commit must use this form:

```text
<type>(<scope>): <message>
```

Examples:

```text
fix(scan): preserve selected module versions during alias grouping
feat(fix): add minimal-safety upgrade planner
docs(readme): explain baseline and exception behavior
test(report): cover sarif output for reachable findings
perf(db): cache OSV lookups by version key
ci(actions): add release verification job
```

### Types

Use one of these types:

- `fix` — correct broken behavior.
- `feat` — add user-visible behavior.
- `docs` — change documentation only.
- `test` — add or correct tests without changing production behavior.
- `refactor` — restructure code without changing behavior.
- `perf` — improve performance without changing behavior.
- `build` — change build tooling or dependencies.
- `ci` — change automation or workflows.
- `chore` — maintenance that fits none of the above.
- `revert` — revert an earlier commit.

### Commit rules

- Write the type and scope in lowercase.
- Use a real scope; prefer the package or subsystem being changed.
- Write the message in the imperative mood: `reject`, `preserve`, `add`, not
  `rejected`, `preserved`, or `added`.
- Do not end the subject with a period.
- Keep each commit focused on one logical change.
- Explain non-obvious reasoning, security impact, and compatibility concerns in
  the commit body.

For a breaking change, add `!` and explain the migration in the body:

```text
feat(scan)!: change default fail-on threshold semantics
```

```text
BREAKING CHANGE: CI policy output now treats moderate findings as blocking unless
explicitly configured.
```

---

## 04 // WRITING PULL REQUESTS

A pull request is not only a diff. It is the record of why the diff should cross
 the boundary into `main`.

### Before opening

- Branch from the latest `main`.
- Keep unrelated cleanup out of the change.
- Add or update tests for every behavior change and bug fix.
- Update documentation when CLI behavior, report output, fix planning, baselines,
  exceptions, or public APIs change.
- Preserve compatibility unless a breaking change was discussed first.
- Review the final diff yourself, including generated and AI-assisted code.

### Pull request titles

Use the same format as commits:

```text
<type>(<scope>): <message>
```

Examples:

```text
fix(scan): preserve selected-version classifications for indirect deps
feat(report): include advisory aliases in SARIF output
docs(contributing): document AI disclosure expectations
```

A correctly formatted title allows the merge commit to preserve the same history
convention.

### Pull request description

Use this template:

````markdown
## Signal

What problem does this change solve?

## Change

What changed, and why was this approach chosen?

## Linked issue

Fixes #

## Security and fail-closed impact

Explain any effect on dependency selection, advisory matching, reachability,
output semantics, remediation planning, auth or network behavior, or public
APIs. State explicitly when there is no security impact.

## Verification

```text
make check
make test-race
make vet
make build
```

Describe the important test cases added or changed.

## Compatibility

State whether the change is backward compatible. Document migrations or breaking
behavior.

## AI assistance

Was AI used to create this pull request or any part of the change?

- [ ] No
- [ ] Yes

If yes:

- Tool or provider:
- Model:
- Used for:
- Files or areas affected:
- Human verification performed:

## Checklist

- [ ] The change is focused and contains no unrelated edits.
- [ ] Commits use `type(scope): message`.
- [ ] Tests cover successful and failure paths.
- [ ] Security-sensitive behavior still fails closed.
- [ ] Go files are formatted.
- [ ] `make check` passes.
- [ ] `make test-race` passes.
- [ ] `make vet` passes.
- [ ] Documentation and examples are updated where needed.
- [ ] AI use is disclosed accurately.
````

### AI-assisted contributions

AI-assisted contributions are allowed. Disclosure is required.

Name the tool or provider and the model when known. Explain what it assisted
with: research, issue writing, implementation, tests, refactoring,
documentation, or review. The contributor remains responsible for every line
submitted.

Do not send secrets, private module metadata, personal data, or undisclosed
vulnerability details to an external AI system. Review generated code for
invented APIs, unsafe defaults, missing error paths, weak tests, licensing
problems, and behavior that fails open.

// AI may help cross the distance. It does not own the decision.

---

## 05 // CODE AND TEST SIGNAL

Follow normal Go conventions and let `gofmt` decide formatting.

Tests should cover both the expected path and the failure path. Security-related
changes should include negative tests proving that invalid, ambiguous, or
missing data fails closed.

Pay particular attention to:

- requested vs selected module versions and MVS behavior;
- direct, indirect, and transitive dependency classification;
- malformed or partial advisory and OSV responses;
- reachability, package loading, and source-to-sink evidence;
- unknown or invalid report keys, baselines, and exceptions;
- CLI parsing, exit codes, and report serialization;
- formatter stability and output contract changes;
- concurrent use when adding caches or shared state.

Place package-level tests beside the affected package. Use a focused integration
or e2e test when behavior crosses scanner logic, vulnerability matching,
reporting, fix planning, or database interactions. Add benchmarks for
performance changes.

---

## 06 // REVIEW AND MERGE

Draft pull requests are welcome for early technical feedback. Mark a pull
request ready only when its description, tests, and documentation are complete.

During review:

- Answer comments directly.
- Push focused follow-up commits.
- Do not resolve a conversation until the concern is addressed or agreement is
  reached.
- Expect maintainers to prioritize correctness, dependency evidence, reproducible
  findings, and fail-closed behavior over convenience.

A pull request is ready to merge when CI passes, the required evidence is
present, review comments are resolved, and a maintainer approves it. Automated
review may assist the process; maintainers make the final decision.

---

## 07 // LICENSE

By submitting a contribution, you agree that it may be distributed under the
repository's GNU General Public License v3.0.

// The threshold is not the door. It is the moment the change becomes trusted.
