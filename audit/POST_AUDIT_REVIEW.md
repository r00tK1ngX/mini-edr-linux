# POST-AUDIT REVIEW — PHASE A
**Project:** Mini EDR for Linux  
**Repository:** `r00tK1ngX/mini-edr-linux`  
**Base branch:** `main`  
**Review branch:** `remediation/phase-a-post-audit-review`  
**Review mode:** Read-only review; no application code modified  
**Date:** 2026-11-06

## 1. Purpose and decision

This review checks whether the existing audit package is internally consistent, correctly scoped to the Python coursework, and sufficiently traceable to serve as the remediation backlog.

**Decision: PHASE A — PARTIAL.** The audit package is useful and contains actionable evidence, but it is not yet a clean, internally consistent acceptance baseline. Resolve the report-quality issues below before using its priorities as an implementation checklist.

This review does not re-run the 214 tests or the empirical probes. The test results below are claims recorded in the audit documents, not independently reproduced by this review.

## 2. Repository baseline and provenance

- The current `main` head returned by GitHub commit search during this review is `7d1968ae465f36f6839bb83220fca0092a62e918`.
- The audit executive summary says it audited `feature/phase-10-slides-demo` at `b1fe164`.
- `AUDIT_BASELINE.md` instead records audit commit `c2745e135092cc121f6eae2b146992ae90de6029`, and records `main` at `f622aa015736d4efb8d53a25e9ab8b2e72bfc747`.
- The reports therefore identify at least three different commit identities and do not clearly establish which exact tree each finding refers to.
- The README currently documents `python3 -m agent.orchestrator`, while the audited roadmap says to replace that with `python3 -m agent.main`. On the current `main` tree, `agent/main.py` exists and `agent/orchestrator.py` returned 404. This discrepancy is confirmed against the current branch.

**Required action:** Add a single immutable audit target SHA to the executive summary, baseline, findings register, and test report. For every remediation, record the baseline SHA and the remediation branch commit being tested. Do not silently mix findings from different commits.

## 3. Internal consistency issues in the audit package

### A-01 — Audit target commit is inconsistent
**Severity:** High (audit traceability)  
**Evidence:** Executive summary, baseline and current main report different SHAs/branches as listed above.  
**Impact:** A finding may refer to code that is not the code currently being remediated.  
**Action:** Reconcile the audit target to one exact commit; identify findings that were checked on another commit and revalidate them.

### A-02 — Test arithmetic is incorrect or ambiguously labelled
**Severity:** Medium  
**Evidence:** `AUDIT_TEST_RESULTS.md` states 214 automated tests, 10/18 passing empirical probes, 8/18 failed, then labels the total as 222 (214 + 8 empirical harnesses) and reports 96.4%. But 214 + 18 probes = 232 probe/test outcomes if each probe is counted as one outcome; 214 + 8 harnesses = 222 executions only if harnesses, not individual probes, are the unit. The 96.4% figure is not a meaningful combined pass rate because the automated tests and empirical probes have different test units and purposes.  
**Action:** Report the suites separately: automated tests 214/214; empirical probes 10/18. Remove the combined 96.4% figure unless a clearly defined and defensible denominator is provided.

### A-03 — Deliverable count does not match inventory
**Severity:** Low  
**Evidence:** Executive summary says 15 audit deliverables, while its inventory lists baseline, file inventory, architecture, 10 phase reports, findings, roadmap, test results and executive summary (17 entries).  
**Action:** Correct the count or inventory.

### A-04 — Remediation action count is not mapped to all findings
**Severity:** Medium  
**Evidence:** Findings register reports 36 findings. Roadmap lists 5 P0 + 4 P1 + 6 P2 + 5 P3 = 20 actions. Several actions consolidate multiple findings, while some findings are deferred or have no explicit disposition. Consolidation is valid, but the mapping is not sufficiently explicit.  
**Action:** Add a complete matrix with one row per finding and exactly one disposition: remediation action, accepted risk with reason, out of scope with reason, duplicate/merged finding with canonical ID, or revalidation required.

### A-05 — Priority labels and academic acceptance are conflated
**Severity:** Medium  
**Evidence:** Executive summary approves academic defense while describing high-priority security blockers; roadmap labels some actions P0 “before defense/demo” and other access-control work P1 “within one week.”  
**Action:** Separate three gates: (1) safe local academic demo, (2) coursework functional acceptance, and (3) production deployment. A finding can be a production blocker without being a coursework scope requirement; however, a known exploitable issue must not be hidden during a demo.

### A-06 — Empirical probe denominator and harness count are unclear
**Severity:** Medium  
**Evidence:** Test report describes eight scratch harness scripts, 18 individual probes, 10 passing and 8 failing. It later uses “8 empirical harnesses” in the total arithmetic.  
**Action:** Distinguish harness count, probe count, and individual test assertions in separate columns. Include exact commands, artifact paths, and reproducibility instructions where those artifacts are available.

## 4. Current-main spot checks performed for this review

These are limited source checks, not a complete re-audit.

| Check | Current source observation | Review result |
|---|---|---|
| Agent entry point | `agent/main.py` exists; `agent/orchestrator.py` was not found on `main` | README quickstart discrepancy confirmed |
| Payload cap | `server/app.py` sets `MAX_CONTENT_LENGTH=64 * 1024` | Finding remains present on reviewed main |
| Alert recurrence | `AlertRepository.create_or_update()` upsert updates title, description, severity and timestamps, but not status | Resolved-alert reopening finding remains present |
| Dashboard rendering | `static/dashboard.js` contains raw `innerHTML` usage in toast construction and additional dynamic UI paths | Requires context-specific sink/source review; do not assume every sink is exploitable |
| Audit target | Current main head differs from the audit baseline commit | Revalidation against current main required |

Important nuance: the presence of `innerHTML` alone does not prove XSS. The source must be attacker-controllable and reach an executable HTML/attribute context. The original XSS probes should be rerun against the exact current remediation baseline after the commit discrepancy is resolved.

## 5. Scope decision for a Python coursework project

### In scope — remediate or explicitly test
- Dashboard DOM/attribute XSS and safe rendering of untrusted telemetry.
- Operator access control and CSRF protection for state-changing web actions, using a small Flask-native design appropriate to a lab.
- Reliable configuration of Flask `SECRET_KEY` and API token validation.
- FIM event preservation across network failures.
- Correct alert recurrence and severity lifecycle.
- Correct detection rule registry and rule-to-documentation alignment.
- Bounded payload handling that supports realistic project telemetry.
- Safe symlink handling and FIM correctness.
- SQLite parameter limits, transaction integrity and concurrent-write behavior.
- Correct heartbeat partial-update semantics.
- Regression tests, E2E tests and reproducible Linux setup.
- Accurate README, API, architecture and test documentation.

### Out of scope for this coursework unless the original assignment explicitly requires it
- eBPF/kernel-level event capture.
- Machine-learning detection.
- PostgreSQL, Redis, Celery or distributed task infrastructure.
- Enterprise mTLS and certificate lifecycle management.
- Automatic process termination or file quarantine.
- Full enterprise SOC/SIEM functionality.
- Mandatory collection of full process command lines. Do not collect extra sensitive process data merely to make documentation match. Prefer correcting documentation if the assignment does not require it.

### Conditional / optional
- Persistent endpoint UUID: useful for cloned lab VMs, but not essential for a single-host or small lab demonstration.
- Telemetry retention: add a simple configurable retention policy only if the demo produces enough data to create a practical storage issue.
- Rate limiting: a small request bound may be appropriate, but adding a new dependency is not automatically justified for a localhost lab.
- FIM metadata fast-path: optimize only with tests that prove no content changes are missed. Metadata equality must not be treated as cryptographic proof of unchanged content in adversarial conditions.

## 6. Corrections to remediation proposals before implementation

1. **SECRET_KEY:** Do not silently generate a new random secret on every application startup as the production configuration strategy. Prefer requiring a configured secret for non-test use, fail fast with a clear error, and allow tests to inject a deterministic test secret. Document secure generation and storage.
2. **MAX_CONTENT_LENGTH:** Do not simply raise the cap to 16 MiB without validating the maximum expected baseline/process payload and enforcing per-field/count limits. Choose a documented bound based on measured project payloads; return a clear 413 response.
3. **FIM retry:** Merely retaining an in-memory old baseline is not a durable outbox. It can still lose intermediate changes across process restart or repeated modifications. For this coursework, use a small durable local pending-event spool or an equivalent design with explicit acknowledgement and tests; avoid introducing a message broker.
4. **Detection rules:** Do not add a rule solely because a document names it. First decide whether the behavior is required by the assignment, define safe observable conditions and evidence, then implement and test it. Avoid claims that simple filename/path heuristics detect all reverse shells or malware.
5. **cmdline:** The roadmap proposes adding process command-line collection, but it is not necessary to meet the stated minimum process-monitoring scope and increases privacy exposure. Correct the documentation unless the assignment rubric explicitly requires it.
6. **XSS:** Prefer DOM APIs and `textContent` for plain text. Where rich markup is required, construct fixed markup and place untrusted values only into text nodes or validated attributes. Avoid a generic hand-written sanitizer.

## 7. Required Phase A outputs before implementation

- One canonical audit target commit SHA.
- Corrected test arithmetic and separate test/probe summaries.
- Corrected deliverable inventory count.
- Finding-to-action disposition matrix covering all 36 entries.
- Scope decision for each finding: in-scope, optional, out-of-scope, duplicate, or needs revalidation.
- Revalidated P0/P1 ordering based on academic-demo risk versus production risk.
- Explicit list of findings that still exist on the canonical baseline.

## 8. Phase A acceptance criteria

Phase A can be marked **VERIFIED** only when:
- All audit reports refer to one immutable baseline commit, or clearly identify which commit each finding applies to.
- All 36 findings have a disposition and traceable remediation/test mapping.
- Test metrics have unambiguous denominators.
- Out-of-scope items are documented with rationale rather than silently ignored.
- Every proposed remediation fits the assignment and has a regression-test strategy.
- No application source code has been modified in this phase.

**Current status: PARTIAL — review report created; reconciliation matrix and source-level revalidation remain outstanding.**
