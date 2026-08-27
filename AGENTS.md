# AGENTS.md

## Subagents

Do not use subagents unless executing a specific `actionplan.md`. Do not launch
review subagents for unrelated work. Do not poll subagents for status; wait for
them to return.

Use two independent roles for each action-plan phase:

- Executor: exactly one `sol` agent at medium reasoning for the phase's first
  implementation pass and every remediation follow-up in that phase.
- Reviewer: exactly one `terra` agent at xhigh reasoning for the phase's
  implementation audits.

Use a new executor and reviewer for each phase. Reuse the same executor and
reviewer throughout one phase's remediation loop. If those labels are
unavailable, use the environment's direct implementation and high-rigor review
equivalents while preserving the two independent roles.

After an executor returns, send the complete phase review set directly to the
designated reviewer. The main agent reviews remediation plans for scope and
architectural alignment and may edit a returned plan directly before handing
it to the executor. Such edits may incorporate authoritative user
clarifications, correct scope, and consolidate the architecture, but must not
invent findings or broaden the governing requirements. The main agent does not
duplicate the reviewer's implementation audit. The main agent performs its own
implementation audit only when repeated review returns for the same phase
trigger the architectural deep-dive rule.

If a reviewer returns the same phase more than three times, pause remediation
and audit the authoritative requirements, architecture documents, and relevant
code. Look for split ownership, duplicated vocabulary, an invalid boundary, or
unnecessary complexity. Consolidate the design around one canonical owner
instead of adding coordinators, forks, flags, or compatibility layers.

Multiple returns do not require a forced direction change. However, two or
three direction changes indicate churn. Consolidate the recent pivots into one
coherent direction and carry it through phase completion.

## Optimization

**IMPORTANT: Optimization should be considered for everything you do**

Minimize loops, memory churn, blocking, and unnecessary allocation. Maximize
parallelism. Prefer pinned application memory where appropriate. Allocate
long-lived buffers once, size them tightly, and reuse them aggressively. Use
compact, well-defined data types and buffers sized only for the task when
supported by the language. All algorithms should be O(1) where possible.

## actionplan.md

An `actionplan.md` is an executable phased plan for another agent.

Do not write user-facing notes, answers, commentary, or reminders in the plan.
Do not repeat constraints already stated in `AGENTS.md`.

Plans must contain concrete phases, important files, exact actions and
locations, risks, and post-cleanup work. Confirm relevant files and current
line numbers before writing the plan. Do not use vague directives such as
"explore."

### Writing an action plan

- Include Summary, Scope, Architecture, and a concrete problem statement or
  goal.
- Name the files expected to change in each phase.
- Sequence dependent work coherently. Phases may overlap, and intermediate
  states do not need to compile because build and test occur in Final
  Validation.
- Do not add a Commit section or phase; the session-level Git rules apply.
- In plan mode, save the final executable plan as `actionplan.md` before
  beginning execution.

### Executing an action plan

- Phase order is sequencing guidance, not a strict scope barrier. Pull work
  forward when it completes an ownership cutover. Do not use a compatibility
  shim merely to traverse phases.
- Spawn exactly one executor for the phase's first implementation pass.
- The main agent handles Final Validation and small evidence-driven fixes found
  there. Delegate large missing implementation pieces back to the phase
  executor.
- After implementation, spawn exactly one independent reviewer for that phase.
  The reviewer must inspect `git diff`, staged changes, untracked files in
  scope, and relevant unchanged integration points.
- Use a new reviewer for each phase and the same reviewer for all follow-ups in
  that phase.
- A phase may close only when its reviewer returns `COMPLETE`. Nice-to-have
  suggestions do not block closure; remediate medium through critical findings
  that impede required behavior, safety, architecture, or integration.
- If files are staged or otherwise changed after a review, the same reviewer
  must verify the final review set before closure. Staging is not itself a
  prerequisite for review.
- When the reviewer returns `NOT COMPLETE`, review `remediationplan.md` for
  scope and architectural alignment, then send it to the same executor. The
  executor owns remediation until that plan contains no phases. Do not request
  another review before the remediation plan is empty.
- Send the complete updated review set back to the same reviewer. Repeat with
  the same pair until the phase is `COMPLETE` or the repeated-review
  architectural deep dive applies.
- Update `actionplan.md` atomically after each completed phase. Inspect later
  phases and update an individual affected phase when the completed work
  materially changes it.
- Do not modify the plan's Summary, Scope, Architecture, constraints, or scope
  clarification while executing it.
- Remove completed phases entirely. Do not record completed work; leave only
  remaining actionable steps.
- Do not defer plan updates until the end.
- Do not add or force-commit `actionplan.md`.
- Commit the phase-scoped tracked changes after the reviewer returns
  `COMPLETE` and the completed phase has been removed.
- Do not build or run tests before every implementation phase is complete.
  Final Validation is owned by the main agent and requires no review subagent.
- Final Validation begins with one complete cleanup pass and the repository's
  full configured formatting, generation, lint, static-analysis, build, and
  test workflows. Resolve genuine findings, use grouped targeted reruns for
  follow-up, and finish with one final full cleanup pass and the necessary
  final verification.

### Reviewer prompt

Use the following prompt for every phase review, replacing `<WORK SCOPE>`,
`<REQUIREMENTS SOURCE>`, and `<REVIEW SET>` with concrete values:

> Audit the complete `<REVIEW SET>` for `<WORK SCOPE>` against every
> requirement in `<REQUIREMENTS SOURCE>` and all applicable repository
> instructions. Review from scratch; do not focus only on the latest fix, and
> do not stop after the first finding.
>
> First, translate the requirements into an explicit acceptance checklist. For
> each requirement, identify the intended behavior, affected components,
> inputs and outputs, constraints, invariants, integration points, and evidence
> needed to prove completion. Then inspect every changed artifact plus relevant
> unchanged callers, callees, dependencies, configuration, generation and
> build logic, documentation, and tests. Look for opportunities to remove
> boilerplate and repetition.
>
> Before evaluating implementation details, build an ownership and authority
> map for every concept, system, subsystem, resource, and stateful workflow in
> scope. Name exactly one authoritative owner for each vocabulary or schema,
> identity, policy, algorithm, mutable fact, physical resource, scheduling or
> admission decision, lifecycle phase, resource obligation, completion signal,
> retry or retirement decision, error classification, and terminal outcome.
> Trace every component that can create, observe, mutate, validate, translate,
> cache, clear, release, or infer each item, including callers, callees,
> callbacks, guards, leases, destructors, queues, controllers, managers,
> helpers, registries, adapters, and cleanup paths. Every ownership transfer
> must have one explicit handoff where the source relinquishes authority and
> the target accepts it; shared access, observation, or execution does not
> imply shared ownership.
>
> Flag split or fractured ownership whenever multiple components can author the
> same concept, enforce the same policy, retain the same custody, independently
> decide the same outcome, or each own only a partial view such that no one
> component can uphold the complete invariant. This applies even when lifecycle
> state is implicit. Look for parallel representations of one vocabulary,
> mirrored structures or flags, duplicated validation or routing, caller and
> callee both compensating for the same failure, multiple cleanup authorities,
> helpers or managers with overlapping mandates, and cross-layer rules that
> require coordinated edits.
>
> For stateful behavior, also flag multiple components storing or deriving the
> same phase, more than one component advancing or terminating the same
> lifecycle, satellite objects advancing or terminating their owner's
> lifecycle, cleanup paths performing hidden cross-owner transitions, and
> correctness that depends on mirrored pending, active, complete, closed,
> released, retained, or terminal facts. Treat repeated defects at different
> boundaries of one concept as architectural evidence of split ownership
> rather than unrelated bugs. Require consolidation under one canonical owner
> with a complete invariant; satellites may carry immutable inputs, receipts,
> projections, or notifications but must not own parallel authority.
>
> Do not accept an added lock, helper, flag, queue, registry, adapter, or
> compatibility layer if it only coordinates split ownership instead of
> eliminating it. Do not misclassify immutable shared access, disjoint
> ownership partitioned by key or resource, a derived read-only projection, or
> replicated data governed by one explicit consistency protocol as split
> ownership. Shared lifetime is not shared mutation authority. When multiple
> writers are genuinely required, one arbitration protocol must be the
> canonical authority for ordering, conflict resolution, invariants, and
> terminal decisions.
>
> Inventory every enum, status, result, error, command, event, identity, and
> payload vocabulary in the review set and build its conversion graph. Flag
> parallel vocabularies representing the same concept in different layers,
> repeated or bidirectional conversion functions, mirrored payload structures,
> and hand-written type switches that require coordinated edits when a variant
> is added. A boundary-specific type is justified only when it has genuinely
> different semantics or authority and conversion occurs once at that
> boundary. One canonical typed vocabulary should own each concept, with
> projections derived mechanically through the language's facilities, schema
> generation, a single registry, or one exhaustive owner-provided conversion.
> Default or catch-all branches that silently collapse new variants are not
> proof of exhaustiveness. Delete unused variants and parallel representations
> before abstracting translators.
>
> For every changed behavior, contract, state or data transition, dependency,
> side effect, or lifecycle, enumerate all applicable paths and boundaries:
> normal operation, empty and limit cases, invalid or duplicate input, partial
> progress, early return, failure, unavailable dependency, capacity
> exhaustion, retry, cancellation, restart, shutdown, and cleanup.
> Where concurrency, asynchronous work, persistence, external services,
> generated code, platform behavior, or compatibility boundaries are relevant,
> enumerate their failure modes and interleavings as well. For each applicable
> path, prove:
>
> - the implementation matches the requirement and preserves its invariants;
> - state and data remain valid through partial progress and failure;
> - side effects occur in the required order and at the intended cardinality;
> - errors are detected, propagated, or made terminal as specified;
> - resources and obligations are acquired, transferred, released, and
>   accounted for correctly;
> - integration behavior is preserved or completely cut over as required;
> - performance, allocation, blocking, security, and observability constraints
>   are respected;
> - tests and validation evidence are deterministic, meaningful, and
>   appropriate for the environment;
> - memory churn and time complexity are reasonable and no safe,
>   behavior-preserving optimization is being missed.
>
> Do not invent durable multi-step recovery protocols or broad
> snapshot-restoration machinery. When a short operation partially fails,
> perform small local cleanup or undo when it is straightforward and safe.
> Otherwise return a precise error and leave a valid, inspectable state with a
> clear idempotent rerun or manual-repair path. Add a multi-step recovery
> protocol only when the requirements explicitly demand one.
>
> Do not assume an operation succeeds because the happy path expects it.
> Challenge implicit assumptions at component boundaries and check interactions
> between changes that are individually correct. Mark a review dimension `NOT
> APPLICABLE` only with a concrete reason.
>
> After the first pass, perform a second adversarial pass beginning with
> boundary conditions, invalid state, dependency failure, partial execution,
> and integration scenarios rather than the happy path. Include
> concurrency and shutdown scenarios when relevant. Re-read the complete review
> set. Rebuild the ownership, authority, and state-transition map from
> consumers, failures, cleanup, and terminal outcomes backward, and compare it
> with the first-pass map. Any disagreement about who owns a concept, policy,
> resource, fact, or transition is a finding.
>
> Treat repeated hand-written code across files as evidence of a contract gap,
> split ownership, duplicated lifecycle authority, or missing canonical
> abstraction until proven otherwise. Seek a design that reduces code and
> future implementation overhead. Compare the result with every authoritative
> architecture and requirements document named by `<REQUIREMENTS SOURCE>` and
> report discrepancies.
>
> Return one consolidated report with every finding, not merely the first
> blocker. For each finding include severity, exact artifact and location,
> failing execution path, violated requirement or invariant, and the minimum
> required correction. Include a coverage ledger mapping every requirement to
> `VERIFIED` or to a finding, so omissions are visible. Say `COMPLETE` only
> when both passes find no unresolved issue.
>
> Treat `<REVIEW SET>` as authoritative and verify that it is complete and
> internally consistent. Do not edit reviewed artifacts or their governing
> plan, specification, ticket, or requirements source. Obey all
> workflow-specific validation timing and state-management restrictions.
>
> If the result is `NOT COMPLETE`, after finalizing the consolidated findings,
> write or replace `remediationplan.md` with an executable remediation plan for
> those findings before returning. This is the review agent's only permitted
> mutation. Include the authoritative review set, findings, concrete phases,
> important files, exact actions and locations, architectural constraints, and
> post-cleanup concerns. Do not add a validation or commit phase, do not edit
> `actionplan.md`, and do not modify implementation or requirements artifacts.

The reviewer must not edit `actionplan.md`. If similar findings recur, stop
patching symptoms and require consolidation of the complete ownership,
authority, vocabulary, and state-transition boundary before closure.

## remediationplan.md

A `remediationplan.md` is an executable phased plan written by the review agent
for the current phase's executor. Before handing it to the executor, the main
agent reviews it for scope and architectural alignment and may edit it directly
as described above. The main agent then follows up with the same executor until
the plan contains no remaining phases. Do not request another review before
the remediation plan is empty.

Do not write user-facing notes, answers, commentary, or reminders in the plan.
Do not repeat constraints already stated in `AGENTS.md`.

The plan must contain concrete phases, important files, exact actions and
locations, risks, and post-cleanup work. Confirm files and line numbers before
writing it. Do not use vague directives such as "explore."

### Writing a remediation plan

- Include Summary, Scope, Architecture, the authoritative review set, and every
  finding being remediated.
- State the problem or goal and name the files expected to change.
- Sequence dependent work coherently; phases may overlap.
- Do not add validation or commit sections or phases. Final Validation remains
  part of `actionplan.md`, and the main agent owns Git.
- Do not broaden scope beyond the review findings or rewrite requirements to
  fit the implementation.

### Executing a remediation plan

- Before executor handoff, the main agent may edit any plan section needed to
  align it with the governing requirements, architecture, review findings, and
  authoritative user clarifications.
- After handoff, the current phase executor owns `remediationplan.md` and
  removes completed remediation phases.
- Pull phases forward when doing so completes an architectural cutover; do not
  add compatibility shims to preserve an intermediate state.
- Update `remediationplan.md` atomically after each completed remediation
  phase.
- Update only individual phases. Do not modify Summary, Scope, Architecture,
  constraints, findings, or scope clarification.
- Remove completed phases entirely. Do not record completed work; leave only
  remaining actionable steps.
- Do not defer updates until the end.
- Do not add or force-commit `remediationplan.md`.

## Code Churn

Do not avoid code churn when it improves the system.

Prioritize performance, clear ownership, proper class/template structure,
healthy architecture, modularity, reuse, and limited blast radius. Reduce
legacy code, fold them into new shared helpers, classes, functions, templates,
factories, or other reusable abstractions where appropriate.

## Code Deduplication

Do not avoid deduplication because the work is large. Do not install system
dependencies to bypass file cleanup. When cleanup is requested, remove all
duplicated code in scope, including cross-file duplication.

Extract shared helpers, classes, functions, templates, factories, or other
reusable abstractions where appropriate. Re-architect code when duplication
indicates a structural problem. Change public and private apis freely. Create
new files freely.

Do not compress lines just to avoid the cap. Repeated lines are a good place
for classes, factories, templates, and shared helpers. Get granular and make
sub templates, sub extractions, factories, enums, vs modifying line lengths.

## Git

Do not make commits unless executing an `actionplan.md`. Post reviews and other
non-actionplan tasks should leave changes uncommitted unless the user
explicitly overrides this rule. Do not add or commit `actionplan.md` or
`remediationplan.md`.

# Tests

Do not add regression tests. This does not mean you cannot add tests. It means
you do not have to add a test for every bug you fix.

## README

Preserve the author's voice in `README.md`. Do not rewrite or remove the
author-written overview, breakdown, quickstart, disclaimer, humor, or tone for
style or completeness. Make targeted additions, or replace text only when it
is explicitly wrong or the user asks for a rewrite. Keep the README concise
and task-oriented: installation, quickstarts, and common commands belong
there; detailed architecture and implementation contracts belong in dedicated
documents linked from the README.

## Atum CLI

Atum is a thin pass-through Cobra CLI around system-installed Terraform,
Ansible/Kubespray, and Flux binaries.

There are exactly three deployment control planes: Terraform owns
infrastructure, Ansible/Kubespray owns Kubernetes, and Flux owns all platform
state deployed into Kubernetes. This includes SOPS decryption, Big Bang and its
child releases, certificate resources, and the Atum operator. Atum may invoke
the upstream tools and observe their native conditions, but invocation and
observation do not transfer reconciliation ownership to Atum.

Do not implement identity, package, workload, release, or other in-cluster
reconciliation in Atum or an imperative post-Flux handoff. If selected charts
cannot express required Keycloak or Vault configuration through values, express
that intent through the narrowly typed Flux-deployed Atum operator. The
operator owns only its declared provider state; Flux remains the owner of its
Kubernetes resources and desired custom resource. Do not use reconciliation
Jobs, in-cluster Atum receipt objects, or generic execution fields. The only
direct Kubernetes object Atum may apply is Flux's SOPS age-key Secret, which
must exist before Flux can decrypt the remaining desired state.

Use the exact platform sequence: `flux bootstrap git` installs and binds only
Flux to the seed Forgejo repository's `main` branch; Atum applies only Flux's
SOPS age-key Secret; normal Flux reconciliation deploys Big Bang; Big Bang
creates its Harbor-backed generic cert-manager `HelmRelease`; Flux gates the
issuer and Certificate resources on that `HelmRelease`; and the Flux-deployed
Atum operator performs final typed Keycloak and Vault configuration after
certificate readiness. Normal `atum apply` and `atum platform apply` must not
call `flux reconcile` to repair or advance Big Bang. An explicitly requested
`atum platform flux reconcile ...` command remains raw Flux passthrough and
does not transfer reconciliation ownership to Atum. Do not manually apply any
platform object other than Flux's SOPS age-key Secret.

Atum is a pure-Go binary. Run every Atum build and Go test with
`CGO_ENABLED=0`; do not introduce a C compiler, libc, or CGO dependency and do
not repair inherited `CC` or `CXX` settings to make repository validation pass.

Keep all task work inside this repository. Do not create temporary directories,
clones, worktrees, or generated artifacts under `/tmp` or elsewhere outside the
repository. Put replaceable task-local state beneath the ignored `./.atum/`
tree and remove it during final cleanup.

Lean on Terraform, Ansible/Kubespray, and Flux as the authoritative
implementation for their respective planes. Do not reproduce their behavior in
Atum, bypass the wrapper with ad hoc deployment commands, or mutate their live
resources by hand to make validation pass.

Keep Atum a thin wrapper over official upstream toolchains. Delegate platform
composition and resource lifecycles to their authoritative upstream engines;
manage only local host systems, credentials, and engine connections where Atum
must bridge those engines or preserve deployment continuity. Platform identity
and service configuration are not local host connections: their Kubernetes
intent remains Flux state and their declared Keycloak and Vault provider state
belongs only to the Atum operator.

Atum is greenfield: no Atum platform has been deployed. Do not implement or
retain data, topology, image, package-path, or secret-schema migrations,
compatibility transitions, or upgrade shims for a prior Atum platform. Reject
unsupported old input and generate the current desired state directly. A
narrow deletion of a proven Atum-owned local file is ordinary cleanup, not a
platform migration. Future upstream updates and the Kubespray
minor-version ladder remain normal atomic selection and application work.

Only the local libvirt target is supported end to end. Keep `infra/vultr` as an
independent Terraform module, but do not advertise or implement it as a
complete Atum platform target until source, registry, domain, network, trust,
and host-continuity handoffs are explicitly designed.

Use `atum pull updates` as the sole writer for upstream-derived desired and
resolved state, including image digests, `atum.json`, `atum.lock.json`,
generated platform values, and Flux manifests. Do not hand-edit coupled
identities or generated artifacts. If updater output is wrong, fix the updater
and rerun it.

Do not use Iron Bank images. Big Bang-maintained package repositories remain
authoritative chart inputs, but any `registry1.dso.mil/ironbank` image reference
they expose is only a runtime compatibility contract. Do not mirror it, use it
as a build base, or deliver it to the cluster. Satisfy the rendered command,
arguments, filesystem, and lifecycle contract with an immutable official
upstream vendor image when compatible; otherwise build reproducibly from the
official upstream project source.

Derive deployment values from the exact selected Big Bang release's
`chart/values.yaml`, schema, templates, values guide, architecture decisions,
and selected package documentation. Big Bang tests and `tests/test-values.yaml`
are non-production verification fixtures, not deployment APIs or production
topology templates.

Prefer a supported official chart with minimal values over a wrapper,
post-renderer, or Atum-authored workload manifest. Before deciding whether an
official image can be mirrored or needs a compatibility build, inspect the
selected release's rendered command, arguments, filesystem paths, user and
group requirements, and controller-owned lifecycle.

Do not modify `./bigbang` or `./kubespray` as part of Atum CLI work. Do not
vendor full upstream Big Bang, Kubespray, or chart sources into this
repository.

Keep upstream payloads ignored and treat local upstream directories as
replaceable development inputs. Do not commit nested repositories.

Keep `./platform` as the standalone Flux platform layer. If chart vendoring is
unavoidable, place the minimal vendored chart under `./platform/charts`, not
root `./charts`.

Publish the exact repository state to the seed Forgejo `main` branch and use it
as Flux's only platform source. Do not create deployment branches, secondary
desired-state repositories, or alternate source activation paths.

Harbor is the delivery authority for every image used by Kubernetes,
Kubespray, Flux, or a platform workload and every Helm chart used by the
cluster. The only payload outside Harbor is the minimal bastion-only seed
payload needed to start Forgejo and Harbor before Harbor exists; never copy it
to cluster nodes. For a selected Big Bang release without native APIs for
them, cert-manager and OpenSearch are Big Bang generic packages backed by
Harbor, not standalone bootstrap or independently reconciled releases.

Terraform owns infrastructure resources, including the libvirt network and its
dnsmasq configuration. Atum owns workstation integration such as
systemd-resolved drop-ins and local CA trust. Do not mutate workstation DNS or
trust through Terraform provisioners, `local-exec`, ad hoc shell commands, or
manual host-file edits; use the Atum wrapper.

Preserve system-binary passthrough behavior: phase commands should forward raw
tool arguments after the phase or action boundary instead of reinterpreting
upstream tool flags.

## Architecture Contract

@CONTRACT.md
