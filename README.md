# security-audit-runstate-lint

A zero-dependency linter for the `run-metadata.json` state contract of [`cloudflare/security-audit-skill`](https://github.com/cloudflare/security-audit-skill): it catches a run that claims `run_status: "complete"` while the coverage ledger still holds unvalidated candidates, and it rejects free-text or misspelled `incomplete_reason` tokens. Why now: that skill is the #1 trending coding-agent skill (29.6k stars this month) and its own issue tracker says the completeness claim is the only machine-readable state with no schema and no check.

Upstream: https://github.com/cloudflare/security-audit-skill

## Upstream and the gap

`security-audit-skill` runs a multi-phase audit inside a coding agent and ships two zero-dependency validators: `validate-findings.cjs` for `findings.json` and `validate-coverage-ledger.cjs` for `coverage-ledger.json`. Both are strict about their own artifacts.

`run-metadata.json` is not covered by either one. Upstream's [issue #78](https://github.com/cloudflare/security-audit-skill/issues/78) documents the hole: `SKILL.md` requires exact fields and exact `incomplete_reason` strings ([SKILL.md:86](https://github.com/cloudflare/security-audit-skill/blob/main/skills/security-audit/SKILL.md#L86), [:123](https://github.com/cloudflare/security-audit-skill/blob/main/skills/security-audit/SKILL.md#L123), [:134](https://github.com/cloudflare/security-audit-skill/blob/main/skills/security-audit/SKILL.md#L134), [:179](https://github.com/cloudflare/security-audit-skill/blob/main/skills/security-audit/SKILL.md#L179)), but `grep -c 'run-metadata\|run_status\|incomplete_reason'` returns `0` in both validators and in `report-schema.json`. The issue's repro is short: a run with an unvalidated `candidate` unit plus `"run_status": "complete"` passes both shipped validators, even though the skill forbids exactly that. A trailing space in `"validation budget exhausted "` also passes.

That is the gap this tool fills: it checks the run's terminal-state claim itself, offline, against the documented contract.

## What it does / does not do

Does:

- validates required fields, `profile`, `scope_paths`, `budget`, `execution_policy`, `run_status`
- enforces the three documented `incomplete_reason` tokens and their mutual exclusion with `complete`
- cross-checks a `complete` claim against `coverage-ledger.json`: no `candidate`, `planned`, `in_progress`, `blocked` or `deferred` units may remain, and `findings.json` must exist
- cross-checks `validation_budget_exhausted` (must leave a `candidate` unit holding the unvalidated fingerprint) and `budget_cannot_fund_reconnaissance_and_reserves` (no ledger units may exist, because no agent ran)
- exits `0` / `1` / `2` and prints stable JSON with `--json`

Does not:

- re-implement `validate-findings.cjs` or `validate-coverage-ledger.cjs`; run those first
- judge whether a finding is a real vulnerability
- resolve the ambiguity for `quick`/scoped runs — issue #78 leaves that open, so this tool only checks what the docs pin down
- touch the network or read the audited repository

## Install

Python 3.8+, no dependencies. Copy `bin/security-audit-runstate-lint` onto your `PATH` (or run it in place).

```bash
python3 bin/security-audit-runstate-lint examples/in/run-contradictory
```

## Usage

```bash
# lint a run directory (run-metadata.json, coverage-ledger.json, findings.json)
python3 bin/security-audit-runstate-lint path/to/run

# machine-readable, stable keys
python3 bin/security-audit-runstate-lint path/to/run --json

# ledger lives elsewhere
python3 bin/security-audit-runstate-lint path/to/run --ledger path/to/coverage-ledger.json

# warnings become failures (CI)
python3 bin/security-audit-runstate-lint path/to/run --strict
```

### JSON output

```json
{
  "tool": "security-audit-runstate-lint",
  "version": "1.0.0",
  "run_dir": "examples/in/run-contradictory",
  "status": "fail",
  "summary": { "errors": 5, "warnings": 0 },
  "findings": [
    {
      "code": "XC004",
      "severity": "error",
      "file": "coverage-ledger.json",
      "message": "complete run still has 1 candidate unit(s): unvalidated work contradicts terminal state (a)",
      "hint": "validate them, or record run_status incomplete with validation_budget_exhausted"
    }
  ]
}
```

`status` is `pass`, `pass_with_warnings` or `fail`. `findings[].code` is stable: `RS0xx` for the metadata contract, `XC0xx` for ledger/findings cross-checks.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | contract satisfied (warnings allowed unless `--strict`) |
| `1` | findings: at least one error, or a warning under `--strict` |
| `2` | usage or input error, e.g. the run directory does not exist |

## Tests

```bash
python3 -m unittest discover -s tests -v
```

22 stdlib-only tests; 19 exercise behaviour through the CLI (exit codes, JSON payloads, example fixtures), 3 cover usage errors and text mode.

## 与同类项目的差异

Searched before writing (`gh search repos "security audit skill"`, `gh search repos "run metadata validator"`, `gh search code "incomplete_reason validation_budget_exhausted"`, 2026-10-31). Results: the only repo in this space is the upstream itself (54k stars); the rest are other audit *skills* (≤449 stars), none of which validates `run-metadata.json`. `gh search repos "run metadata validator"` returned nothing and the code search returned nothing. Upstream ships two artifact validators but, per issue #78, nothing reads `run-metadata.json`; this tool is the missing third validator and deliberately does not duplicate the other two.

## Limitations

- The documented token list is taken from `SKILL.md` at commit `HEAD` on 2026-10-30; if upstream adds a reason, pass it in a new release.
- Only checks contract shape and cross-artifact consistency, not audit quality.
- `quick`/scoped `run_status` semantics are undefined upstream (issue #78, point 1); this tool accepts either terminal value for those profiles.
- Expects `coverage-ledger.json` to be a JSON array of units and `findings.json` to be a JSON array, matching upstream's validators.

## License

MIT
