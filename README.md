# ci-sentinel 🛡️

**Security auditor for SEVEN CI ecosystems — GitHub Actions, GitLab CI/CD,
Jenkins, CircleCI, Azure Pipelines, Bitbucket Pipelines and Travis CI** — finds
the supply-chain and injection flaws a YAML linter can't see, *before* an
attacker's pull/merge request runs code with your repository secrets.

Available as an **MCP server** (for Claude / Cursor / any agent) and a
**pay-per-call HTTP API** (x402 USDC or a prepaid card key).

Give it your `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`,
`.circleci/config.yml`, `azure-pipelines.yml`, `bitbucket-pipelines.yml` and/or
`.travis.yml` (each file is auto-routed to the right analyzer) and get a
**CRITICAL / VULNERABLE / RISKY / HARDENED** verdict with the exact flaws.

## What it catches that a linter can't

| Class | What ci-sentinel does |
|---|---|
| 💉 **Expression injection (inter-step / inter-job taint)** | Taints untrusted `${{ github.event.* }}` (issue/PR title, body, comment, review, branch name, commit message, **label name, fork repo identity, edited-from values**) to a `run:` shell **or** `actions/github-script` sink — and **follows it across `steps.<id>.outputs.*`, `needs.<job>.outputs.*`, `env:` vars, `matrix` values and reusable-workflow `inputs.*`**. An attacker who hides the untrusted value behind an intermediate output is still caught; a per-file grep is not. |
| 🎭 **Pwn requests** | `pull_request_target` / `workflow_run` that **check out untrusted fork code** in the privileged, secret-bearing context = arbitrary code execution with your secrets. |
| 🔑 **Token permissions** | Excessive `GITHUB_TOKEN` scopes (`write-all`, `contents:write`, `id-token:write`), missing `permissions:` blocks, and **secrets exposed to untrusted triggers**. |
| 🔁 **Reusable workflows** | `workflow_call` callers passing untrusted data across the boundary as `inputs.*`, and **`secrets: inherit`** handing the full secret set to a reusable workflow on an untrusted trigger. |
| 📌 **Action pinning** | Third-party actions (and **reusable-workflow `uses:`**) on **mutable tags/branches** instead of a commit SHA (the `tj-actions/changed-files`-style hijack), resolved through the **transitive action graph**. |
| 🖥️ **Self-hosted RCE** | Self-hosted runners reachable from **public-repo PRs** (RCE on your own infra), and **OIDC `id-token` trust** misuse. |

### …and the same depth for **GitLab CI/CD** (`.gitlab-ci.yml`)

| Class | What ci-sentinel does |
|---|---|
| 💉 **CI-variable injection** | Taints untrusted GitLab variables (`CI_COMMIT_REF_NAME/BRANCH/TAG`, `CI_MERGE_REQUEST_TITLE/DESCRIPTION/SOURCE_BRANCH_NAME`, commit message/author, triggering-user fields) interpolated into `script:` — **following the taint through `variables:` and `extends:` templates**. Knows the SAFE vars (`CI_COMMIT_SHA`, `CI_MERGE_REQUEST_IID`, `CI_PROJECT_ID`, …) so it doesn't flag every `$CI_`. |
| 🎭 **Fork merge-request pwn** | Jobs reachable from **fork MR pipelines** (`merge_request_event`, `only: merge_requests`) that carry **secrets / a broad `CI_JOB_TOKEN` / `id_tokens` (OIDC)**, or that run **privileged work (deploy/publish/`kubectl`/`terraform`) with no `when: manual` gate**. |
| 📦 **`include:` supply-chain** | `include:` from a **remote URL** or another **project/component on a moving (non-SHA) ref** — foreign pipeline code merged into yours. |
| ☣️ **Artifact / cache poisoning** | An **untrusted job** writes an artifact/cache that a **privileged downstream job consumes and executes** (`needs:`/`dependencies:` or a shared cache path) — a cross-job **and cross-pipeline** escalation. |

### …and five more CI systems, same taint model

| Ecosystem | What ci-sentinel catches |
|---|---|
| 🔧 **Jenkins** (`Jenkinsfile`) | Command injection from `params.*` / `env.CHANGE_*` / `ghprb*` / SCM data into `sh`/`bat`/`powershell` (through `environment{}` bindings); credential-leak (`credentials()`/`withCredentials` printed or baked into a GString); Groovy `evaluate()`/`load` RCE; missing `input()` approval gate; unsafe `agent any`. |
| ⭕ **CircleCI** (`.circleci/config.yml`) | Shell injection from `<< pipeline.git.branch/tag >>` / pipeline parameters into `run:`; unpinned **orbs** (`@volatile` / bare major); fork-PR **context secret** exposure with no `type: approval` gate; privileged deploy with no approval. |
| 🟦 **Azure Pipelines** (`azure-pipelines.yml`) | Macro injection from `$(Build.SourceBranch)` / `$(System.PullRequest.SourceBranch)` / commit message into `script:`/`bash:`/`pwsh:`; untrusted **templates** from a foreign repo resource; fork **variable-group** secret exposure; unpinned repository resources. |
| 🪣 **Bitbucket Pipelines** (`bitbucket-pipelines.yml`) | Shell injection from `$BITBUCKET_BRANCH` / `$BITBUCKET_TAG` / `$BITBUCKET_PR_DESTINATION_BRANCH` / commit message expanded unquoted into `script:`; **secured/deployment-variable** exposure on externally-triggerable PR pipelines; unpinned **pipes** (`:latest`); deployments with no `trigger: manual` gate. |
| 🚦 **Travis CI** (`.travis.yml`) | Shell injection from `$TRAVIS_BRANCH` / `$TRAVIS_PULL_REQUEST_BRANCH` / `$TRAVIS_COMMIT_MESSAGE` expanded unquoted into a lifecycle hook; **secure-env** PR/fork secret exposure; `deploy:` stages with no `on:` branch/condition gate. |

### …plus two deep cross-domain detectors a one-shot agent can't replicate

| Detector | What ci-sentinel catches |
|---|---|
| ☁️ **OIDC cloud-trust misconfiguration** (Terraform / CloudFormation / GCP workload-identity / Azure federated-credential) | Models the **cloud half** of CI OIDC: the trust policy of the IAM role / WIF pool / federated app. Flags a `sub` condition with a broad wildcard (`repo:org/*`, `repo:*`), **no `sub` condition at all** (any workflow on the issuer assumes the role), a repo pinned but ref/environment **un**pinned (any branch assumes), the bare `pull_request` subject (fork-reachable), or an unpinned `aud`. Then **correlates** the IaC trust with the CI side (a workflow that mints `id-token` reachable from an untrusted trigger) and **escalates to critical** when the chain is reachable end-to-end. No single-file linter catches this — it spans the CI claim and the cloud trust policy. |
| 🔧 **Jenkins shared libraries** (`@Library` → `vars/*.groovy`) | Taints an untrusted pipeline value (PR title / branch / build parameter) passed to a shared-library global-var step **through the library's `call()` interior** to an internal `sh`/`bat` sink — the Jenkins parity of orb/template/composite-action cross-file taint, **invisible when reading only the `Jenkinsfile`**. Also flags `@Library` imports on a **mutable ref** (a branch / default version) as supply-chain risk. |

Each analyzer knows the **SAFE** variables (SHAs, numeric ids, trusted slugs —
`BITBUCKET_COMMIT`, `TRAVIS_PULL_REQUEST`, `pipeline.git.revision`, …) and the
SAFE OIDC trusts (`sub` pinned to `repo:org/repo:ref:refs/heads/main` /
`:environment:prod` with `aud` set) so it doesn't flag every `$VAR` or every
trust. Zero false positives on hardened configs.

It is a real static analyzer: a line-aware workflow YAML parser → a model of
triggers/jobs/steps/permissions/actions/outputs/needs → an inter-step/inter-job
taint resolver + permission + supply-chain detectors → a scored verdict with
per-finding **file:line**, the **full taint path**, concrete **remediation**, and a
**SARIF 2.1.0** report (with `codeFlows`) you can upload to **GitHub code scanning**.

### …and it doesn't just flag — it FIXES, and it GRADES

| Premium | What you get |
|---|---|
| 🔧 **Auto-remediation (the exact fix)** | For each finding ci-sentinel produces the **concrete change**: the corrected YAML/Groovy snippet **and a unified diff** you can apply — pin the action/orb/pipe to an immutable SHA/version, env-bind + quote the injected expression, drop write-all to least privilege, insert the manual/approval gate, pin the OIDC `sub`/`aud`, move the hardcoded secret to the store (and rotate it). Not "you have a bug" but **"change THIS to THIS"**, with a confidence label (`exact` / `template` / `guided`) so you know what's drop-in vs. what needs a value filled. Findings carry a stable `fingerprint` for de-duplication, and the SARIF results carry inline `fixes`. |
| 📋 **Compliance scorecard (A–F)** | A CIS-like CI security benchmark scored **A–F** with a **PASS / FAIL / WARN / N/A breakdown per control** (least privilege, component pinning, no secrets to forks, no self-hosted on public PRs, OIDC pinned, no hardcoded secrets, no pwn checkout, gated deploys, no injection, no cross-job poisoning). Each control lists the **finding ids** that drove its verdict — defensible to a security team. A directly-exploitable **critical** flaw caps the grade (one open RCE/secret-exfil path dominates the posture). |
| 🛰️ **Live threat-intelligence feed (the data moat)** | Every `uses:` / orb / pipe in your config is checked against a **live, server-side feed of KNOWN-compromised CI components**, **ingested on a cron from public sources — [OSV.dev](https://osv.dev) and the [GitHub Security Advisory](https://github.com/advisories) database (`ecosystem=actions`)** — and merged onto a curated seed of the flagship incidents (`tj-actions/changed-files` CVE-2025-30066, `reviewdog/action-setup` CVE-2025-30154 and its transitive dependents, the `aquasecurity/trivy-action` tag force-push, Ultralytics). It knows that `tj-actions/changed-files@v45` is **poison** and that the same action **SHA-pinned to a clean commit** or **upgraded to `@v46`** is **safe** — a distinction a static YAML scan or a local linter **cannot** make, because it has no feed. The feed lives **only on the hosted server** (the thin client never carries it); `GET /feed/status` surfaces its freshness. A **live reputation signal** (stars / last-commit / archived / does-the-repo-still-resolve) additionally flags **archived/abandoned** components and **dangling** references that are takeover-bait. **This is the access-moat that justifies the hosted, paid model:** the value is the live DATA, not the compute. |
| 🪤 **Tag-rewrite & imposter detection (live ref→commit)** | Give ci-sentinel the commit SHA you *expected* a mutable ref to be (from your lockfile/SBOM) and it resolves what the tag **currently** points at upstream — flagging a **tag-rewrite / force-push** (`@v2` now runs a *different* commit than you reviewed — the exact tj-actions attack), a **deleted/dangling ref**, or a **suspiciously recent move**. It also pairs **typosquat detection with the live reputation signal** to confirm **impersonation** — `actons/checkout` (a near-miss of `actions`) whose repo is a freshly-stood-up, low-star or dangling imposter — vs. a legitimately-named small fork (no false positive). And because the feed is keyed by **component identity**, a compromised action is caught **no matter which CI system references it** (cross-CI) — the piece a mono-CI scanner structurally can't have. |

## MCP server (free)

```json
{
  "mcpServers": {
    "ci-sentinel": { "command": "npx", "args": ["-y", "ci-sentinel-mcp"] }
  }
}
```

Tool: **`audit_ci_security`**. Pass `files` (a map of workflow filename → YAML) or
`source` (one workflow). The free tier returns the verdict and **how many** issues
of each kind were found.

## Deep audit (`deep: true`) — two ways to pay

The deep audit returns **every finding with file:line, the full inter-step/
inter-job injection taint path, the transitive action supply-chain graph, a
concrete fix (corrected snippet + unified diff) per finding, an A–F compliance
scorecard with a per-control breakdown, and a SARIF 2.1.0 document with inline
`fixes`** (uploadable to GitHub code scanning via `github/codeql-action/upload-sarif`).

- 💳 **Card (Stripe)** — buy a prepaid key at `https://ci-sentinel.vercel.app/pro/checkout`,
  then set `"env": { "CI_SENTINEL_KEY": "<key>" }` in your MCP config.
- 🪙 **x402 (USDC)** — AI agents pay per call automatically (USDC on Base), no signup.

## HTTP API

```
POST /audit          # free, rate-limited — verdict + per-severity counts
POST /pro/audit      # deep — pay-per-call (x402) or Authorization: Bearer <key>
POST /mcp            # MCP-over-HTTP (free)
GET  /presence       # live active sessions (last 5 min)
GET  /                # this landing page
```

```bash
curl -X POST https://ci-sentinel.vercel.app/audit \
  -H 'Content-Type: application/json' \
  -d '{"files":{".github/workflows/ci.yml":"name: CI\non: pull_request_target\n..."}}'
```

## Why hosted? (the moat)

The npm package is a **thin client**: it runs no analysis locally. The parser,
taint engine, action-graph resolver and detector knowledge base run **server-side
only**, behind the paywall — so the premium material (findings, evidence, taint
paths, remediation) never lands on the caller's machine. A `npm pack` ships only
`dist/mcp.js`, `dist/mcpServer.js` and `dist/types.js`; the engine is never in the
tarball (verified automatically by `npm run test:moat`).

## How the live feed stays live (the update pipeline)

The threat-intelligence feed is **ingested, not hard-coded**. A periodic job runs
server-side:

1. **Fetch** advisories from two public sources (no paid keys):
   - **GitHub Security Advisory DB** — `GET /advisories?ecosystem=actions` (public;
     `GITHUB_TOKEN` only raises the rate limit, it is **not required**).
   - **OSV.dev** — the `GitHub Actions` ecosystem, queried for the components we
     already track plus everything GHSA just surfaced (so OSV enriches them).
2. **Normalize** each advisory into a `ThreatRecord` — owner/name split, incident
   class inferred from the advisory text (tag-rewrite / maintainer-compromise /
   malicious / CVE…), severity bucketed, the affected version range parsed into a
   selector, the **fixed version** captured (so an upgraded pin does **not** fire).
3. **Merge** the rows onto the curated seed (`ingestFeed`: union refs, keep the
   worst severity, widen the affected range, de-dup by identity).
4. **Store** the snapshot in Cloudflare KV. Every `/pro/audit` reads it back via
   `kvFeedProvider`, **falling back to the compiled seed** if KV is cold — so the
   detector is never blocked and never worse than the static baseline.

```bash
# run the refresh once (live: hits the real public APIs)
node scripts/refreshFeed.mjs
# dry run with no network (produces the seed-only snapshot)
CI_SENTINEL_NO_NET=1 node scripts/refreshFeed.mjs
```

Schedule it with **Vercel Cron** (`{ "path": "/internal/refresh-feed",
"schedule": "0 */6 * * *" }`, guarded by `FEED_REFRESH_TOKEN`) or a scheduled
GitHub Action that runs `node scripts/refreshFeed.mjs`. `GET /feed/status` reports
the live snapshot's version, `generatedAt` and record count — the public freshness
proof. None of this ships in the npm client.

## Development

```bash
npm install
npm run build          # tsc
npm test               # engine + parser + taint + SARIF + autofix + compliance + corpus tests (851 checks)
npm run test:moat      # lock-proof: tarball ships no engine, deep degrades w/o pay
npm run dev:http       # local HTTP server (FORCE_LISTEN)
```

---

Heuristic static analysis of the workflow YAML you provide — it cannot see
repo-level default token permissions, branch protections or org policy, and does
not execute the pipeline. Treat findings as leads to verify.

Source & docs: https://github.com/Baneado98/ci-sentinel · MIT
