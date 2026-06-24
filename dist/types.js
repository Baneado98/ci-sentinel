// Shared types for ci-sentinel — the CI/CD (GitHub Actions) security auditor.
//
// The analysis pipeline is: parse workflow YAML -> build a model of jobs/steps/
// triggers/permissions/actions -> run detectors (taint of untrusted input to a
// `run:` sink, privileged-context pwn, permission/secret exposure, action pinning,
// self-hosted runner, OIDC trust) -> score -> render.
//
// FREE tier returns ONLY counts (how many of each severity, by category). DEEP
// (paid) returns the full Finding list with file:line evidence, the taint path
// (source expression -> sink step) and remediation. The premium material never
// runs on the user's machine — the engine is server-side only (the moat).
export {};
