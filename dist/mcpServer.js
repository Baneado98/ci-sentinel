// ci-sentinel MCP server (THIN CLIENT — the moat).
//
// This module ships in the npm tarball. It runs NO analysis locally: every audit
// (free quick verdict AND the deep premium scan) is performed by the hosted
// server. The engine (parser, taint analysis, action-graph, detectors) NEVER
// reaches the user's machine, so the premium material (findings, evidence, taint
// paths, remediation) cannot be extracted from the package.
//
//   • FREE  → POST ${PRO_BASE}/audit      (server runs deep=false + redacts to counts)
//   • DEEP  → POST ${PRO_BASE}/pro/audit  (paid: x402 USDC or prepaid key)
//
// Without a key, deep=true shows the UPSELL (it does NOT run the premium scan).
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
const PRO_BASE = (process.env.CI_SENTINEL_PRO_URL ?? "https://ci-sentinel.vercel.app").replace(/\/+$/, "");
const PRO_KEY = (process.env.CI_SENTINEL_KEY ?? "").trim();
const CHECKOUT_URL = (process.env.CHECKOUT_URL ?? "https://ci-sentinel.vercel.app/#pro").trim();
const CHECKOUT_BASE = CHECKOUT_URL.replace(/#pro$/, "").replace(/\/+$/, "");
const DEEP_PITCH = [
    "every finding with its exact file:line, the offending snippet and severity (free shows only HOW MANY)",
    "the full taint path: untrusted input laundered through step/job outputs, env vars, reusable-workflow inputs (Actions) or variables:/extends: (GitLab) — followed to the run:/script: sink (a per-file grep can't see this)",
    "GitLab CI/CD coverage too: CI-variable injection, fork-MR secret/OIDC exposure, untrusted include:, fork-execution gaps and artifact/cache poisoning across jobs",
    "SEVEN CI ecosystems in one tool — also Jenkins (Jenkinsfile injection/credential-leak/Groovy-eval/approval-bypass), CircleCI (pipeline.git.* injection, unpinned orbs, fork context-secret exposure, missing approval gate), Azure Pipelines (Build.SourceBranch/System.PullRequest.* injection, untrusted templates, fork variable-group secrets, unpinned resources), Bitbucket Pipelines (BITBUCKET_BRANCH/PR/commit-message injection, secured-variable fork exposure, unpinned pipes, ungated deployments) and Travis CI (TRAVIS_BRANCH/PR_BRANCH/commit-message injection, secure-env PR exposure, ungated deploys)",
    "CROSS-FILE taint into foreign code the agent can't read: GitHub composite-action interiors, GitLab remote/project include: bodies, CircleCI ORB command sources and Azure TEMPLATE bodies are resolved & analyzed, so an untrusted value that lands in a run:/script: INSIDE the orb/template/action/include is caught (a single-file scan misses it)",
    "HARDCODED SECRETS across all seven ecosystems — AWS/GitHub/GitLab/Slack/Google/Stripe/npm keys, PEM private keys and generic high-entropy secrets committed in CI config — with zero false positives on the correct ${{ secrets.X }}/$VAR/credentials('id')/vault references, and redacted evidence",
    "the transitive action supply-chain graph (an action that uses another unpinned action) — not just your top-level uses:",
    "a SARIF 2.1.0 report with codeFlows AND inline `fixes`, ready to upload to GitHub code scanning (Security tab)",
    "AUTO-REMEDIATION: a CONCRETE fix per finding — the exact corrected snippet AND a unified diff you can apply (pin to a SHA, env-bind + quote the injected expression, add the least-privilege permissions block, insert a manual/approval gate, pin the OIDC sub/aud, move the hardcoded secret to the store) — not just 'you have a bug' but 'change THIS to THIS'",
    "a COMPLIANCE SCORECARD: an A–F grade against a CIS-like CI security benchmark (least privilege, component pinning, no secrets to forks, no self-hosted on public PRs, OIDC pinned, no hardcoded secrets, no pwn checkout, gated deploys, no injection, no poisoning) with a PASS/FAIL/WARN breakdown per control — defensible to a security team",
];
function upsellText(target) {
    return [
        `🔒 Deep CI/CD security audit for "${target}" is a premium check.`,
        "",
        "The free audit gives the CRITICAL / VULNERABLE / RISKY / HARDENED verdict and",
        "HOW MANY issues were found per severity. The DEEP scan opens everything — it adds:",
        ...DEEP_PITCH.map((p) => `  • ${p}`),
        "",
        "Two ways to unlock it — pick whichever fits you:",
        "",
        "  💳  Pay with a card (Stripe) — for humans/teams:",
        `      Buy a prepaid API key at  ${CHECKOUT_BASE}/pro/checkout`,
        "      then set it in your MCP config:",
        '          "env": { "CI_SENTINEL_KEY": "<your-key>" }',
        "",
        "  🪙  Pay per call with x402 (USDC) — for AI agents with a wallet:",
        `          POST ${PRO_BASE}/pro/audit   (an x402-aware client pays automatically)`,
        "",
        "Tip: re-run this audit without deep=true for the free verdict right now.",
    ].join("\n");
}
// Low-level POST to a hosted path. `paid` controls whether the Bearer key is sent
// and the UA tag; the body is forwarded verbatim.
async function postHosted(path, body, paid) {
    const auth = paid && PRO_KEY ? { Authorization: `Bearer ${PRO_KEY}` } : {};
    const ua = paid ? "ci-sentinel-mcp/deep" : "ci-sentinel-mcp/free";
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 25_000);
    try {
        const res = await fetch(`${PRO_BASE}${path}`, {
            method: "POST",
            signal: ctrl.signal,
            headers: { Accept: "application/json", "Content-Type": "application/json", "User-Agent": ua, ...auth },
            body: JSON.stringify(body),
        });
        if (res.status === 401 || res.status === 402 || res.status === 403)
            return { ok: false, status: res.status, error: "payment-required" };
        if (res.status === 429)
            return { ok: false, status: 429, error: "rate-limited" };
        if (!res.ok)
            return { ok: false, status: res.status, error: `server responded ${res.status}` };
        return { ok: true, status: 200, result: (await res.json()) };
    }
    catch (err) {
        return { ok: false, status: 0, error: String(err?.message ?? err) };
    }
    finally {
        clearTimeout(t);
    }
}
async function fetchHosted(body, deep) {
    return postHosted(deep ? "/pro/audit" : "/audit", { ...body, deep }, deep);
}
async function fetchDiff(body) {
    return postHosted("/pro/diff", body, true);
}
function badge(v) {
    return v === "CRITICAL" ? "🔴 CRITICAL"
        : v === "VULNERABLE" ? "🟠 VULNERABLE"
            : v === "RISKY" ? "🟡 RISKY"
                : v === "HARDENED" ? "🟢 HARDENED" : "⚪ UNKNOWN";
}
export function renderText(r) {
    const lines = [];
    lines.push(`${badge(r.verdict)}  —  ${r.workflowsAnalyzed} workflow(s)  (risk score ${r.score}/100)`);
    lines.push(r.summary);
    if (r.tier === "deep") {
        const comp = r.premium?.compliance;
        if (comp) {
            lines.push("");
            lines.push(`Compliance scorecard: GRADE ${comp.grade}  (${comp.score}/100) — ${comp.passed} pass / ${comp.warned} warn / ${comp.failed} fail${comp.na ? ` / ${comp.na} n/a` : ""}`);
            for (const c of comp.controls) {
                const mark = c.status === "pass" ? "✅" : c.status === "warn" ? "⚠️ " : c.status === "fail" ? "❌" : "➖";
                lines.push(`  ${mark} ${c.id} ${c.title}`);
                if (c.status === "fail" || c.status === "warn")
                    lines.push(`        ${c.detail}`);
            }
        }
        if (r.findings.length) {
            lines.push("");
            lines.push("Findings:");
            for (const f of r.findings)
                lines.push(...renderFinding(f));
        }
        const g = r.premium?.actionGraph;
        if (g) {
            lines.push("");
            lines.push(`Action supply-chain: ${g.totalActions} action(s), ${g.unpinned} unpinned, ${g.transitiveResolved} resolved transitively.`);
        }
        if (r.premium?.sarif) {
            const nRes = r.premium.sarif.runs[0]?.results.length ?? 0;
            lines.push("");
            lines.push(`SARIF 2.1.0: ${nRes} result(s) with codeFlows — in premium.sarif. Upload to GitHub code scanning (github/codeql-action/upload-sarif) or any SARIF viewer.`);
        }
        if (r.premium?.perWorkflow?.length && r.premium.perWorkflow.length > 1) {
            lines.push("");
            lines.push("Per-workflow:");
            for (const w of r.premium.perWorkflow)
                lines.push(`  • ${w.file}: ${w.verdict} (${w.findings} finding(s))`);
        }
    }
    else {
        lines.push("");
        lines.push(`Findings: ${r.findingsCountText} (counts only).`);
        if (r.findingsSummary.total > 0) {
            const cats = Object.entries(r.findingsSummary.byCategory).map(([c, n]) => `${n}×${c}`).join(", ");
            lines.push(`  By category: ${cats}`);
            lines.push("  🔒 The free tier shows HOW MANY issues and of what kind — not where or how.");
            lines.push("     Run with deep=true (premium) for each finding: file:line, the taint path");
            lines.push("     (which attacker field reaches which run: sink), the action graph and fixes.");
        }
    }
    lines.push("");
    lines.push(`⚠️  ${r.disclaimer}`);
    return lines.join("\n");
}
function renderFinding(f) {
    const out = [`  • [${f.severity.toUpperCase()}] ${f.title}`];
    out.push(`      ${f.detail}`);
    out.push(`      ↳ ${f.file}:${f.line}${f.job ? `  job=${f.job}` : ""}${f.trigger ? `  on=${f.trigger}` : ""}`);
    if (f.evidence)
        out.push(`      evidence: ${f.evidence}`);
    if (f.taint) {
        out.push(`      taint: ${f.taint.source} (${f.taint.sourceKind})${f.taint.via.length ? ` → ${f.taint.via.join(" → ")}` : ""} → ${f.taint.sink}`);
        if (f.taint.steps && f.taint.steps.length) {
            out.push(`      codeFlow:`);
            for (const s of f.taint.steps)
                out.push(`        ↳ ${s.file}:${s.line}  ${s.label}`);
        }
    }
    if (f.remediation)
        out.push(`      fix: ${f.remediation}`);
    if (f.fix) {
        out.push(`      ✎ ${f.fix.title} [${f.fix.confidence}]`);
        if (f.fix.diff) {
            out.push(`      patch:`);
            for (const dl of f.fix.diff.split("\n"))
                out.push(`        ${dl}`);
        }
        else {
            out.push(`        ${f.fix.rationale}`);
        }
    }
    return out;
}
function diffBadge(v) {
    return v === "INTRODUCES_RISK" ? "🔴 INTRODUCES_RISK"
        : v === "REDUCES_RISK" ? "🟢 REDUCES_RISK"
            : "⚪ NEUTRAL";
}
function deltaMark(k) {
    return k === "introduced" ? "➕🔴" : k === "aggravated" ? "⬆️🟠" : k === "removed" ? "➖🟢" : k === "mitigated" ? "⬇️🟢" : "▪️";
}
export function renderDiff(r) {
    const lines = [];
    const sign = r.scoreDelta > 0 ? `+${r.scoreDelta}` : `${r.scoreDelta}`;
    lines.push(`${diffBadge(r.verdict)}  —  risk ${r.before.score}→${r.after.score} (${sign})`);
    lines.push(r.summary);
    lines.push("");
    lines.push(`Delta: ${r.introducedCount} introduced, ${r.aggravatedCount} aggravated, ${r.removedCount} removed, ${r.mitigatedCount} mitigated, ${r.unchangedCount} unchanged.`);
    const headline = r.deltas.filter((d) => d.kind !== "unchanged");
    if (headline.length) {
        lines.push("");
        lines.push("Changes:");
        for (const d of headline) {
            const sev = d.kind === "aggravated" || d.kind === "mitigated"
                ? `${d.beforeSeverity}→${d.afterSeverity}`
                : (d.severity ?? "").toUpperCase();
            lines.push(`  ${deltaMark(d.kind)} [${d.kind.toUpperCase()}] (${sev}) ${d.title}`);
            const f = d.finding;
            lines.push(`      ↳ ${f.file}:${f.line}${f.job ? `  job=${f.job}` : ""}${f.trigger ? `  on=${f.trigger}` : ""}`);
            if (f.taint)
                lines.push(`      taint: ${f.taint.source} (${f.taint.sourceKind}) → ${f.taint.sink}`);
            if (d.kind === "introduced" && f.fix)
                lines.push(`      ✎ to undo the risk: ${f.fix.title}`);
        }
    }
    lines.push("");
    lines.push(`⚠️  ${r.disclaimer}`);
    return lines.join("\n");
}
function hostUnavailableText(label, detail) {
    return [
        `⚠️  Could not reach the ci-sentinel service to audit "${label}".`,
        `    (${detail})`,
        "",
        `    The audit runs server-side; retry shortly. Health: ${PRO_BASE}/health`,
    ].join("\n");
}
function diffUpsellText() {
    return [
        "🔒 Differential CI/CD security analysis (diff_ci_security) is a premium check.",
        "",
        "It takes the BEFORE and AFTER state of a workflow/pipeline (e.g. a PR that edits",
        ".github/workflows/x.yml or a Jenkinsfile) and tells you exactly which security",
        "findings the change INTRODUCES, REMOVES or AGGRAVATES — with a verdict",
        "(INTRODUCES_RISK / REDUCES_RISK / NEUTRAL) you can wire into a PR gate. Your agent",
        "can't compute this delta itself: it has no stable BEFORE→AFTER security reconciliation.",
        "",
        "Two ways to unlock it:",
        "",
        "  💳  Pay with a card (Stripe):",
        `      Buy a prepaid API key at  ${CHECKOUT_BASE}/pro/checkout`,
        '      then set  "env": { "CI_SENTINEL_KEY": "<your-key>" }  in your MCP config.',
        "",
        "  🪙  Pay per call with x402 (USDC) — for AI agents with a wallet:",
        `          POST ${PRO_BASE}/pro/diff   (an x402-aware client pays automatically)`,
    ].join("\n");
}
// Parse the { before, after } diff args. Each side is { files | source } (+ the
// optional cross-file body channels). Returns the forwardable body or null.
function parseDiffArgs(a) {
    const side = (raw) => {
        if (!raw || typeof raw !== "object")
            return null;
        let files;
        if (raw.files && typeof raw.files === "object") {
            files = {};
            for (const [k, v] of Object.entries(raw.files))
                if (typeof v === "string")
                    files[k] = v;
            if (Object.keys(files).length === 0)
                files = undefined;
        }
        const source = raw.source ? String(raw.source) : undefined;
        if (!files && !source)
            return null;
        const out = { files, source };
        for (const key of ["actionYmls", "includeYmls", "orbYmls", "templateYmls", "sharedLibYmls"]) {
            const m = raw[key];
            if (m && typeof m === "object") {
                const sm = {};
                for (const [k, v] of Object.entries(m))
                    if (typeof v === "string")
                        sm[k] = v;
                if (Object.keys(sm).length)
                    out[key] = sm;
            }
        }
        return out;
    };
    const before = side(a?.before);
    const after = side(a?.after);
    if (!before || !after)
        return null;
    const nb = before.files ? Object.keys(before.files).length : 1;
    const na = after.files ? Object.keys(after.files).length : 1;
    return { body: { before, after }, label: `${nb} before / ${na} after file(s)` };
}
function parseInputArgs(a) {
    let files;
    if (a?.files && typeof a.files === "object") {
        files = {};
        for (const [k, v] of Object.entries(a.files))
            if (typeof v === "string")
                files[k] = v;
        if (Object.keys(files).length === 0)
            files = undefined;
    }
    const source = a?.source ? String(a.source) : undefined;
    if (!files && !source)
        return null;
    const label = files ? `${Object.keys(files).length} workflow file(s)` : "(workflow source)";
    return { files, source, label };
}
export function buildMcpServer() {
    const server = new Server({ name: "ci-sentinel", version: "0.1.0" }, { capabilities: { tools: {} } });
    server.setRequestHandler(ListToolsRequestSchema, async () => ({
        tools: [
            {
                name: "audit_ci_security",
                description: "Audit GitHub Actions, GitLab CI/CD, Jenkins, CircleCI, Azure Pipelines, Bitbucket Pipelines AND Travis CI for security flaws BEFORE you merge or trust them — SEVEN CI ecosystems in one tool. Give it your CI config — the contents of .github/workflows/*.yml, your .gitlab-ci.yml, your Jenkinsfile, your .circleci/config.yml, your azure-pipelines.yml, your bitbucket-pipelines.yml and/or your .travis.yml (it auto-detects which CI system each file is) — and it returns a CRITICAL / VULNERABLE / RISKY / HARDENED verdict. " +
                    "GitHub Actions: script/expression INJECTION (attacker-controlled ${{ github.event.* }} — issue/PR title, body, comment, branch name, commit message, label name, fork repo identity — into run: or actions/github-script), following taint ACROSS steps.<id>.outputs.*, needs.<job>.outputs.*, env vars, matrix values, reusable-workflow inputs.* and composite-action interiors; pull_request_target / workflow_run 'pwn requests'; reusable-workflow misuse (untrusted data over workflow_call, 'secrets: inherit'); excessive GITHUB_TOKEN permissions; unpinned third-party actions incl. transitive supply chain (tj-actions/CVE-2025-30066 class); self-hosted-runner RCE; OIDC/id-token misuse; broken if: gates. " +
                    "GitLab CI/CD: injection from untrusted CI variables (CI_COMMIT_REF_NAME/BRANCH/TAG, CI_MERGE_REQUEST_TITLE/DESCRIPTION/SOURCE_BRANCH_NAME, commit message/author) interpolated into script:, following taint through variables: and extends: templates AND through remote/project include: files (cross-file, the included file's sinks are resolved & analyzed); secrets / broad CI_JOB_TOKEN / id_tokens (OIDC) exposed to fork merge-request pipelines; include: from untrusted remote/foreign-project sources not pinned to a SHA; rules/only/except that let a fork MR run privileged jobs without a manual gate; and artifact/cache POISONING where an untrusted job feeds bytes a privileged downstream job executes (cross-job & cross-pipeline). " +
                    "Jenkins (declarative + scripted Jenkinsfile): command INJECTION from untrusted input (build params.*, multibranch env.CHANGE_*/BRANCH_NAME, the GitHub PR-builder ghprb* vars like ghprbCommentBody, SCM commit data) interpolated into a sh/bat/powershell GString — following taint through pipeline/stage environment{} bindings; credential exposure (a credentials()/withCredentials secret printed with echo or baked into a shell GString, defeating log masking); Groovy evaluate()/Eval/load over untrusted input (sandbox bypass / RCE); approval-bypass (a privileged deploy/publish step reachable from a PR/comment build with no input() gate); and unsafe 'agent any' running untrusted PR code on a privileged executor. " +
                    "CircleCI (.circleci/config.yml): shell INJECTION from untrusted pipeline values (<< pipeline.git.branch >> / << pipeline.git.tag >> the attacker names, or a pipeline parameter set by an API/PR trigger) interpolated into a run: command; UNPINNED ORBS on a mutable version (@volatile / a bare major / dev: tag = supply-chain, the orb runs in your pipeline with your contexts); CROSS-FILE ORB INJECTION — an untrusted value passed to an orb-command parameter that the published orb's OWN source pipes into an internal run: sink (the orb's interior is resolved & analyzed, a flow a single-file scan can't see); fork-PR CONTEXT SECRET exposure (a job attaching an org context reachable from forked-PR builds without a type: approval gate); and missing approval gate before a privileged deploy job. " +
                    "Azure Pipelines (azure-pipelines.yml): macro INJECTION from untrusted predefined variables ($(Build.SourceBranch)/$(Build.SourceBranchName) the attacker names, $(System.PullRequest.SourceBranch) on fork PRs, $(Build.SourceVersionMessage) commit message) substituted into script:/bash:/pwsh: text, following taint through variables: bindings; UNTRUSTED TEMPLATES pulled from a foreign repository resource (runs in your pipeline with your secrets); CROSS-FILE TEMPLATE INJECTION — an untrusted value passed as a template parameter that the foreign template's OWN body pipes into an internal script:/bash: sink (the template interior is resolved & analyzed); fork variable-GROUP / secret exposure on PR-triggered pipelines; and unpinned repository resources on moving refs. " +
                    "Bitbucket Pipelines (bitbucket-pipelines.yml): shell INJECTION from attacker-named variables ($BITBUCKET_BRANCH / $BITBUCKET_TAG / $BITBUCKET_PR_DESTINATION_BRANCH, or a crafted commit message) expanded unquoted into a script: line in a default/pull-requests pipeline; SECURED / deployment-variable fork exposure (a PR pipeline reachable from external contributors that reads repository/deployment secrets); UNPINNED PIPES (a pipe: on :latest / a floating tag = supply-chain, the pipe runs in your step with your secrets); and ungated DEPLOYMENTS (a deployment: step with no trigger: manual reachable from PR/branch). " +
                    "Travis CI (.travis.yml): shell INJECTION from attacker-named TRAVIS_* variables ($TRAVIS_BRANCH / $TRAVIS_PULL_REQUEST_BRANCH / $TRAVIS_TAG / $TRAVIS_COMMIT_MESSAGE) expanded unquoted into a lifecycle hook (before_script/script/after_*); secure-env PR exposure (encrypted secure: vars present on a PR-buildable config that can leak to same-repo branch PRs / opted-in forks); and ungated DEPLOYS (a deploy: with no on: branch/condition gate that fires on any ref). " +
                    "HARDCODED SECRETS (all seven ecosystems): credentials committed verbatim in any CI config — AWS access key ids (AKIA/ASIA), GitHub tokens (ghp_/gho_/ghs_/github_pat_), GitLab/npm/Slack/Google/Stripe keys, PEM private keys, and generic high-entropy secrets assigned to secret-shaped keys — while correctly suppressing the SAFE indirect references (${{ secrets.X }}, $VAR, << pipeline... >>, $(Var), credentials('id'), Key Vault / vault refs) so you get the real leaks with zero false positives; evidence is redacted so the report never re-leaks the credential. " +
                    "OIDC CLOUD-TRUST MISCONFIGURATION (cross-domain, IaC): include your Terraform / CloudFormation / GCP workload-identity / Azure federated-credential and ci-sentinel models the CLOUD side of OIDC — the trust policy of the IAM role / pool / app that backs CI — and flags the catastrophic-but-common misconfigurations: a `sub` condition with a broad wildcard (repo:org/*, repo:*), NO sub condition at all (any workflow on the issuer can assume the role), a repo pinned but ref/environment UNpinned (any branch can assume), the bare `pull_request` subject (fork-reachable), or an unpinned `aud`. It then CORRELATES the IaC trust condition with the CI side (a workflow that mints id-token reachable from an untrusted trigger) and escalates to critical when the chain is reachable end-to-end — a flow no single-file CI linter catches because it spans the CI claim and the cloud trust policy. " +
                    "JENKINS SHARED LIBRARIES (@Library, cross-file): provide the library's vars/<name>.groovy bodies (sharedLibYmls) and ci-sentinel taints an untrusted pipeline value (a PR title / branch / build parameter) passed to a shared-library global-var step THROUGH the library's call() interior to an internal sh/bat sink — the Jenkins parity of orb/template/composite-action cross-file taint, invisible when reading only the Jenkinsfile — plus flags @Library imports pinned to a mutable ref (a branch / default version) as supply-chain risk. " +
                    "The deep tier returns every finding with file:line, the full taint path and a SARIF 2.1.0 report with codeFlows, uploadable to GitHub code scanning. Use it whenever reviewing, writing or accepting CI config. Heuristic static analysis, not a guarantee.",
                inputSchema: {
                    type: "object",
                    properties: {
                        files: {
                            type: "object",
                            description: "Map of filename -> content, e.g. { \".github/workflows/ci.yml\": \"name: CI\\non: ...\", \".gitlab-ci.yml\": \"stages: ...\", \"Jenkinsfile\": \"pipeline { ... }\", \".circleci/config.yml\": \"version: 2.1\\n...\", \"azure-pipelines.yml\": \"pool: ...\", \"bitbucket-pipelines.yml\": \"pipelines: ...\", \".travis.yml\": \"language: ...\" }. Mix GitHub Actions, GitLab CI, Jenkins, CircleCI, Azure Pipelines, Bitbucket Pipelines and Travis CI files freely — each is routed to the right analyzer by its name/shape. Audit a whole repo's CI at once.",
                            additionalProperties: { type: "string" },
                        },
                        source: { type: "string", description: "A single CI file's content (a GitHub Actions workflow, a .gitlab-ci.yml, a Jenkinsfile, a .circleci/config.yml, an azure-pipelines.yml, a bitbucket-pipelines.yml, a .travis.yml, or an IaC OIDC trust policy .tf/.json; auto-detected). Use instead of 'files' for one file." },
                        sharedLibYmls: { type: "object", description: "OPTIONAL (Jenkins): bodies of shared-library global vars keyed by the var NAME (the vars/<name>.groovy basename), e.g. { \"deployTo\": \"def call(Map config){ sh \\\"... ${config.target}\\\" }\" }. Lets the deep audit taint an untrusted pipeline value THROUGH a @Library step into the library's internal sh sink (cross-file). There is no public registry for shared libs, so supply the bodies here.", additionalProperties: { type: "string" } },
                        deep: { type: "boolean", description: "When true, runs the PREMIUM deep audit: every finding with file:line, the full injection taint path, the transitive action supply-chain graph and concrete remediation. Requires an API key (set CI_SENTINEL_KEY in your MCP env); without one you'll get unlock instructions. The free quick verdict needs no key." },
                    },
                },
            },
            {
                name: "diff_ci_security",
                description: "DIFFERENTIAL CI/CD security check for a workflow/pipeline CHANGE — the tool a PR gate needs. Give it the BEFORE and AFTER state of your CI config (e.g. a pull request that edits .github/workflows/*.yml, .gitlab-ci.yml, a Jenkinsfile, .circleci/config.yml, azure-pipelines.yml, bitbucket-pipelines.yml, .travis.yml or an IaC OIDC trust policy) and it reports exactly which security findings the change INTRODUCES, REMOVES or AGGRAVATES, plus a single verdict: INTRODUCES_RISK (block the change), REDUCES_RISK (the change hardens CI) or NEUTRAL. " +
                    "It runs the full 7-ecosystem deep engine on both states and reconciles the two finding sets by a LINE-INDEPENDENT identity, so an edit that merely shifts line numbers does NOT look like it introduced/removed a flaw — only a REAL security change shows up. For every introduced finding you get the file:line, the taint path and the concrete fix to undo the risk; for removed ones you see what the change fixed. This is the answer your own agent can't compute by reading the after-state alone: it has no principled BEFORE→AFTER security delta. " +
                    "Use it on every PR that touches CI config — wire INTRODUCES_RISK to a failing status check. Provide each side as { files: {name: yaml} } (or { source } for one file). Premium: requires an API key (set CI_SENTINEL_KEY) or pays per call via x402. Heuristic static analysis, not a guarantee.",
                inputSchema: {
                    type: "object",
                    properties: {
                        before: {
                            type: "object",
                            description: "The BEFORE state of the CI config (the base / target branch). Same shape as audit input: { files: {filename: yaml}, ... } or { source: \"...\" }. May also carry actionYmls/includeYmls/orbYmls/templateYmls/sharedLibYmls for cross-file resolution.",
                            properties: {
                                files: { type: "object", additionalProperties: { type: "string" } },
                                source: { type: "string" },
                                actionYmls: { type: "object", additionalProperties: { type: "string" } },
                                includeYmls: { type: "object", additionalProperties: { type: "string" } },
                                orbYmls: { type: "object", additionalProperties: { type: "string" } },
                                templateYmls: { type: "object", additionalProperties: { type: "string" } },
                                sharedLibYmls: { type: "object", additionalProperties: { type: "string" } },
                            },
                        },
                        after: {
                            type: "object",
                            description: "The AFTER state of the CI config (the PR / head branch). Same shape as 'before'.",
                            properties: {
                                files: { type: "object", additionalProperties: { type: "string" } },
                                source: { type: "string" },
                                actionYmls: { type: "object", additionalProperties: { type: "string" } },
                                includeYmls: { type: "object", additionalProperties: { type: "string" } },
                                orbYmls: { type: "object", additionalProperties: { type: "string" } },
                                templateYmls: { type: "object", additionalProperties: { type: "string" } },
                                sharedLibYmls: { type: "object", additionalProperties: { type: "string" } },
                            },
                        },
                    },
                    required: ["before", "after"],
                },
            },
        ],
    }));
    server.setRequestHandler(CallToolRequestSchema, async (req) => {
        const { name, arguments: args } = req.params;
        try {
            if (name === "diff_ci_security") {
                const parsed = parseDiffArgs(args);
                if (!parsed)
                    return { content: [{ type: "text", text: "Error: provide 'before' and 'after', each a { files: {filename: yaml} } or { source: \"...\" } describing that state of the CI config." }], isError: true };
                if (!PRO_KEY)
                    return { content: [{ type: "text", text: diffUpsellText() }] };
                const dr = await fetchDiff(parsed.body);
                if (dr.ok && dr.result)
                    return { content: [{ type: "text", text: renderDiff(dr.result) }] };
                if (dr.error === "payment-required") {
                    return { content: [{ type: "text", text: `🔒 Your CI_SENTINEL_KEY was rejected (HTTP ${dr.status}). It may be invalid or expired.\n\nGet or renew a key → ${CHECKOUT_BASE}/pro/checkout` }] };
                }
                return { content: [{ type: "text", text: hostUnavailableText(parsed.label, `diff analysis unavailable — ${dr.error}`) }], isError: true };
            }
            if (name !== "audit_ci_security")
                return { content: [{ type: "text", text: `Unknown tool: ${name}` }], isError: true };
            const parsed = parseInputArgs(args);
            if (!parsed)
                return { content: [{ type: "text", text: "Error: provide 'files' (map of workflow filename -> YAML) or 'source' (one workflow's YAML)." }], isError: true };
            const deep = Boolean(args?.deep);
            const a = args;
            const strMap = (o) => {
                if (!o || typeof o !== "object")
                    return undefined;
                const out = {};
                for (const [k, v] of Object.entries(o))
                    if (typeof v === "string")
                        out[k] = v;
                return Object.keys(out).length ? out : undefined;
            };
            const body = { files: parsed.files, source: parsed.source };
            // forward optional cross-file resolution channels when supplied.
            for (const key of ["actionYmls", "includeYmls", "orbYmls", "templateYmls", "sharedLibYmls"]) {
                const m = strMap(a?.[key]);
                if (m)
                    body[key] = m;
            }
            if (deep) {
                if (!PRO_KEY)
                    return { content: [{ type: "text", text: upsellText(parsed.label) }] };
                const pro = await fetchHosted(body, true);
                if (pro.ok && pro.result)
                    return { content: [{ type: "text", text: renderText(pro.result) }] };
                if (pro.error === "payment-required") {
                    return { content: [{ type: "text", text: `🔒 Your CI_SENTINEL_KEY was rejected (HTTP ${pro.status}). It may be invalid or expired.\n\nGet or renew a key → ${CHECKOUT_BASE}/pro/checkout\n\nMeanwhile, re-run without deep=true for the free verdict.` }] };
                }
                return { content: [{ type: "text", text: hostUnavailableText(parsed.label, `deep audit unavailable — ${pro.error}`) }], isError: true };
            }
            const free = await fetchHosted(body, false);
            if (free.ok && free.result)
                return { content: [{ type: "text", text: renderText(free.result) }] };
            if (free.error === "rate-limited") {
                return { content: [{ type: "text", text: `⏳ The free tier is rate-limited (HTTP 429). Wait a bit, or unlock unlimited use via the deep tier → ${CHECKOUT_BASE}/pro/checkout` }], isError: true };
            }
            return { content: [{ type: "text", text: hostUnavailableText(parsed.label, `free audit unavailable — ${free.error}`) }], isError: true };
        }
        catch (err) {
            return { content: [{ type: "text", text: `ci-sentinel error: ${err?.message ?? err}` }], isError: true };
        }
    });
    return server;
}
