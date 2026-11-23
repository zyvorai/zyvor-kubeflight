---
hero:
  eyebrow: CI
  title: PR and CI integration
---

## Only what the change introduced

```bash
# on the base branch (or from the last green run), keep the JSON report
kubeflight check deploy/ --format json --output base.json --fail-on never

# on the PR
kubeflight check deploy/ --baseline-report base.json --fail-on-new high --format pr-comment --output comment.md
```

`--baseline-report` compares this run with an earlier JSON report. Findings are matched on `(id, resource, title)`, so changed evidence is not "new"; a finding whose severity rose counts as new (`previous_severity` is set). Duplicates are counted, not collapsed.

- `--fail-on-new [SEVERITY]` (default `low`) exits 3 only when new findings at or above that severity exist, regardless of how many old findings remain; it replaces `--fail-on`. It needs `--baseline-report`.
- `--format json` adds a `diff` key (`new`, `resolved`, `unchanged`, scores); `--format sarif` sets `baselineState` (`new`/`unchanged`) on each result; `markdown` and `text` append the change section.
- `--min-severity` limits what is displayed; the gate always sees every finding.

```bash
kubeflight diff-report old.json new.json                     # text
kubeflight diff-report old.json new.json --format markdown   # comment-ready, with hidden marker
kubeflight diff-report old.json new.json --fail-on-new high  # exit 3 on new high/critical
```

Reports are validated (32 MiB, shape and severities); a malformed report is an exit-2 error. `POST /api/diff` takes `{old, new}`, and `POST /api/check` / `POST /api/values` accept `baseline_report`.

## PR comment / Step Summary markdown

`--format pr-comment` writes markdown for `GITHUB_STEP_SUMMARY` or a PR comment: a hidden `<!-- kubeflight-pr-comment -->` marker (so a comment step can find and update its own comment), the headline, the new-vs-baseline table when `--baseline-report` is given, and all findings collapsed in a `<details>` block. Output is capped below GitHub's 65,536-character comment limit, and manifest-controlled text is escaped (table separators, HTML, link syntax, `@mentions`).

## GitHub Action

```yaml
- uses: zyvorai/zyvor-kubeflight@main
  with:
    path: deploy/
    profile: restricted
    baseline-report: base/kubeflight-report.json
    fail-on-new: high
    sbom: |
      sboms/payments.cdx.json
    advisories: advisories.yaml
    allow-registry: |
      ghcr.io/acme/*
```

New inputs: `profile`, `profile-file`, `baseline-report`, `fail-on-new`, `image-policy`, `allow-registry`, `sbom`, `advisories` (newline-separated lists), `pr-comment` (output path, default `kubeflight-comment.md`, also an output). The Step Summary is now published before the gate can fail the job, so a failing run still shows why. Inputs reach the shell only through environment variables.
