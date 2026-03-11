# Run Mode — Threat Model and Deployment Requirements

**Status:** DESIGN — targets VAR Core v1.0, Run mode in v1.1  
**Audience:** SREs and platform engineers evaluating whether to deploy NonSudo in Run mode.

---

## 1. Purpose and Non‑Goals

Run mode is the highest-assurance deployment of NonSudo. It is designed so that:

- **Every tool call from the AI agent to protected upstreams is mediated by NonSudo.**
- **Bypassing NonSudo requires defeating workload identity or egress controls, not just misconfiguring an API key.**
- **Verification remains offline and self-contained** (VAR Core v1.0) — Run mode changes *how* receipts are produced, not *how* they are verified.

This document focuses on:

- **Bypass paths in Walk mode** that Run mode is meant to close.
- **Requirements for non-bypassable enforcement** (secretless execution, workload identity, constrained egress).
- **The minimum viable Run implementation path** for v1.1.
- **Explicit out-of-scope items** for v1.1 (what Run will *not* guarantee).

Run mode is an *operator-facing* construct: an SRE should be able to read this document and answer, “If we satisfy these constraints, what attacks still work and which ones do not?”

---

## 2. Bypass Paths in Walk Mode

Walk mode is the v1.0 production mode. It provides strong evidence (signed pre-/post-receipts, budgets, VAR-Money semantics) but is **bypassable** if the AI agent or its hosting environment is misconfigured.

This section enumerates the main bypass paths that SREs should assume remain possible in Walk mode.

### 2.1 Direct Credential Bypass

**Description:** The agent process holds long-lived credentials (API keys, OAuth tokens, private keys) that allow it to call upstream systems directly, without going through NonSudo.

- Examples:
  - Stripe secret key exported as `STRIPE_SECRET_KEY` in the agent pod.
  - Cloud provider credentials with direct access to a database or message queue.
  - SSH keys mounted into the agent container.
- Consequences:
  - Tool calls performed with these credentials produce **no receipts at all**.
  - VAR-Money invariants (budgets, post-receipts, dedupe) do not apply to these calls.

### 2.2 Alternate Network Path Bypass

**Description:** Even if the agent does not hold credentials, there may exist **alternate egress paths** to the same upstreams that do not traverse the NonSudo proxy.

- Examples:
  - Service mesh sidecar with direct outbound to `api.stripe.com` in addition to the NonSudo proxy.
  - Node-level egress rules that allow `0.0.0.0/0` and do not enforce “proxy-only” routing.
  - Misconfigured DNS that resolves the upstream hostname differently for the proxy vs. the agent.
- Consequences:
  - An attacker who can influence the agent (prompt injection, compromised weights, hostile fine-tune) can route traffic over the alternate path.
  - The operator sees a mixture of receipt-backed and receipt-less activity in the upstream audit logs.

### 2.3 Out-of-Band Tool Implementations

**Description:** The policy declares a tool (e.g., `transfer_funds`) that is *intended* to be implemented via NonSudo, but the model or application code can also reach a second implementation directly.

- Examples:
  - MCP tool registered both via NonSudo adapter *and* as a raw HTTP tool.
  - Application-layer wrapper that bypasses NonSudo for “emergency” or “debug” paths.
- Consequences:
  - Operators may believe “all refunds go through NonSudo” while a subset uses the bypass path.
  - Verification of a receipt chain provides a lower bound, not a complete account of actions.

### 2.4 Human-in-the-Loop and Backchannel Bypass

**Description:** The agent can ask a human (or another service) to perform an operation outside NonSudo, using channels that NonSudo cannot see.

- Examples:
  - “Please click this Stripe dashboard button and confirm when done.”
  - “Open a terminal and run this shell script.”
- Consequences:
  - NonSudo receipts accurately record what the agent *asked*, but the high-risk action may occur through human backchannels.
  - This is primarily a **governance and UX** problem; Run mode cannot fully close it.

### 2.5 Observability-Only Configurations

**Description:** Policy or runtime configuration intentionally or accidentally sets:

- `mode: crawl` or `enforcement: false`, or
- Rules that ALLOW with no money-action tagging even for high-risk tools.

Consequences:

- Receipts exist, but **no enforcement** occurs. Upstreams remain directly reachable, and budgets are not enforced.
- Operators may overestimate protection if they do not track the declared mode per workflow.

---

## 3. Requirements for Non‑Bypassable Enforcement (Run Mode)

Run mode’s goal is **non-bypassable enforcement for protected upstreams**: if an upstream action is executed, either:

- There is a corresponding NonSudo receipt chain that passes L1–L4, **or**
- The upstream access was obtained by breaking the surrounding identity or network controls (i.e., outside the assumed threat model).

To achieve this, Run mode adds three hard requirements on top of Walk:

- **Secretless execution** — no long-lived secrets in the agent.
- **Workload identity** — upstreams accept identity-bound tokens only, not raw secrets.
- **Constrained egress** — the only network path to protected upstreams is through NonSudo.

These are operator/SRE obligations as much as product behavior.

### 3.1 Secretless Execution

**Objective:** The AI agent and its immediate runtime never hold long-lived secrets that can be used to call protected upstreams directly.

**Requirements:**

- **No raw API keys or shared secrets**:
  - `STRIPE_SECRET_KEY`, raw DB passwords, and similar secrets MUST NOT be mounted into the agent workload.
  - Where secrets are required, they MUST be mounted only into the NonSudo proxy (or a short-lived signing service) in a separate trust domain.
- **Short-lived, audience-bound tokens only:**
  - When the agent needs to talk to NonSudo, it uses:
    - A workload identity token (OIDC/SPIFFE), or
    - A short-lived session-bound token minted by the platform.
  - These tokens are **not** valid directly against protected upstreams.
- **Configuration isolation:**
  - Tool configuration (endpoints, client IDs, audiences) lives with the proxy, not the agent.
  - Any environment variables that would enable direct upstream access (e.g., raw hostnames, keys) are forbidden from the agent pod spec by policy.

SRE enforcement checklist:

- Periodically scan agent workloads for banned environment variable names and mounted secrets.
- Confirm that the only credentials available to the agent are those used to authenticate *to NonSudo*, not to the upstream.

### 3.2 Workload Identity (OIDC/SPIFFE)

**Objective:** Both the agent and the NonSudo proxy authenticate using workload identity rather than shared secrets. Upstream systems authorize based on this identity.

**Requirements:**

- **Agent → NonSudo:**
  - The agent authenticates to the NonSudo proxy using:
    - A signed OIDC token (e.g., `aud: nonsudo-proxy`, `sub: agent-workload-id`), or
    - A SPIFFE SVID presented over mTLS (`spiffe://org/env/agent-service`).
  - The proxy validates the identity and injects it into the `workflow_manifest` (e.g., `agent_workload_id`).
- **NonSudo → Upstream:**
  - For protected upstreams, credential form MUST be:
    - A workload identity token issued to the proxy (e.g., `aud: stripe-proxy`, `sub: nonsudo-proxy`), or
    - A service account token minted per proxy identity.
  - The upstream MUST authorize requests based on the proxy’s identity, not on a re-usable raw secret.
- **Receipts:**
  - Run-mode manifests MUST record:
    - `deployment_mode: run`
    - `agent_workload_id`
    - `proxy_workload_id`
  - These fields MUST be signed and verifiable under L1/L2.

SRE enforcement checklist:

- Verify that upstream RBAC does not accept raw API keys or passwords from agent workloads.
- Ensure that disabling or misconfiguring workload identity for the proxy breaks upstream access (by design).

### 3.3 Constrained Egress

**Objective:** The only path from the agent to protected upstreams is through NonSudo. Any attempt at direct access should fail at the network layer.

**Requirements:**

- **Perimeter egress controls:**
  - Node and namespace egress policies MUST block direct access from agent workloads to:
    - Protected upstream hostnames (e.g., `api.stripe.com`),
    - Internal services that implement money-moving operations.
  - Allowed egress from agent workloads SHOULD be limited to:
    - NonSudo proxy endpoints (gRPC/HTTP),
    - Observability infrastructure (logging, metrics) as needed.
- **Service mesh / sidecar configuration:**
  - Any service mesh or sidecar MUST be configured so that:
    - Routes to protected upstreams **only** exist from the NonSudo proxy workload.
    - Attempts to create new routes from agent workloads are blocked or require privileged change.
- **DNS and naming consistency:**
  - DNS records for protected upstreams MUST resolve identically for the agent and the proxy.
  - “Shadow” hostnames for bypassing the proxy (e.g., `api-stripe-direct.internal`) MUST not exist or MUST be blocked for agent workloads.

SRE enforcement checklist:

- Use periodic synthetic checks from agent pods to confirm that direct TLS connections to protected upstreams fail.
- Confirm that firewall and mesh configuration changes are part of a controlled change-management process.

### 3.4 Operational Requirements and SLOs

Run mode adds **operational blast radius**: if the proxy is down, money-moving actions cannot proceed.

Operators SHOULD:

- Define SLOs for proxy availability (e.g., 99.9% over 30 days).
- Define clear runbooks for degraded states (e.g., TSA down, budget store degraded) in which:
  - Enforcement remains strict for money actions (FAIL CLOSED where required by VAR Core).
  - Non-money or read-only actions may still proceed with explicit degraded receipts.
- Ensure that on-call engineers can:
  - Identify whether a workflow is in Crawl, Walk, or Run from receipts alone.
  - Explain to auditors what Run mode guarantees that Walk mode does not.

---

## 4. Minimum Viable Run Implementation Path (v1.1)

This section describes a **minimal, ship-ready** Run mode for v1.1. It is intentionally conservative: the requirements are the smallest set that meaningfully raise assurance above Walk mode while remaining feasible for most cloud-native SRE teams.

### 4.1 Phase 0 — Pre‑Reqs (Walk Mode Baseline)

Before enabling Run mode, the deployment MUST:

- Operate successfully in **Walk mode** in production with:
  - VAR Core v1.0 conformance.
  - VAR-Money v1.0 enabled for money actions.
  - Receipt chains routinely verified offline in CI or a periodic job.
- Have **policy bundles** that:
  - Correctly tag money actions (`money_action: true`).
  - Define budgets and VCB limits for high-risk tools (e.g., `stripe-refund-v1`).
- Have at least one runbook for:
  - Proxy crashes (`recovery_event` receipts).
  - Budget warnings and caps (`budget_warning` receipts).

### 4.2 Phase 1 — Workload Identity and Secret Diet

Goals:

- Remove long-lived upstream secrets from the agent.
- Establish workload identity between agent, proxy, and upstream.

Minimal steps:

- Enable OIDC or SPIFFE for agent and proxy workloads.
- Migrate upstream authentication for protected systems so that:
  - Only the proxy’s workload identity can obtain upstream access tokens.
  - Agent workload identities lack direct access roles.
- Scan and eliminate:
  - Raw API keys in agent environment variables.
  - Persistent credentials mounted into agent pods.

Exit criteria:

- Killing workload identity for the proxy breaks all money actions, even in Walk mode.
- Killing workload identity for the agent only prevents it from talking to NonSudo, not directly to upstreams (which were never permitted).

### 4.3 Phase 2 — Egress Lockdown

Goals:

- Make NonSudo the **sole egress path** from agents to protected upstreams.

Minimal steps:

- Implement namespace- or workload-level egress policies:
  - Deny all outbound from agent workloads except:
    - NonSudo proxy endpoints.
    - Observability endpoints.
- Configure service mesh/sidecars (if present) so that:
  - Routes to protected upstream hostnames exist only for proxy workloads.
  - Attempts to send traffic from agent pods to these hostnames are rejected.
- Add continuous checks:
  - Synthetic tests that attempt direct upstream connections from agent pods and assert failure.

Exit criteria:

- It is operationally *easier* to update NonSudo policy than to create a network bypass.

### 4.4 Phase 3 — Run Mode Flag and Receipts

Goals:

- Enable `mode: run` in policy and surface it in receipts.

Minimal steps:

- Add `mode: run` to `nonsudo.yaml` for selected workflows.
- Ensure the proxy:
  - Fails closed for money and read-write actions per VAR Core RI-9.
  - Emits manifests with `deployment_mode: run`, `agent_workload_id`, and `proxy_workload_id`.
- Extend operational dashboards and reports to:
  - Distinguish Crawl, Walk, Run workflows.
  - Alert if a Run workflow’s receipts show degraded behavior (e.g., repeated `RECOVERY_INCOMPLETE`).

Exit criteria:

- At least one production workflow runs in `mode: run` with:
  - Verified offline L1–L4 chains.
  - Clear evidence that direct upstream access from agent pods is blocked.

---

## 5. Explicit Out‑of‑Scope Items for Run v1.1

Run mode v1.1 is intentionally scoped. The following are **out of scope** and MUST NOT be inferred from “Run mode” in receipts or documentation:

### 5.1 Model and Prompt Integrity

- Run mode **does not** guarantee:
  - That the model weights have not been tampered with.
  - That prompts are free of injection or manipulation.
- It records what the agent attempted to do and enforces policy on tool calls; it does not certify the *correctness* of those attempts.

### 5.2 Human and Backchannel Behavior

- Run mode **does not**:
  - Prevent humans from performing out-of-band actions (e.g., clicking UI buttons).
  - Capture actions taken in third-party dashboards, shells, or consoles.
- It may record that the agent *asked* for human help, but not what the human ultimately did.

### 5.3 Cross‑Tenant or Cross‑Cloud Identity

- v1.1 does not attempt to:
  - Standardize workload identity semantics across all cloud providers.
  - Provide federated identity guarantees across tenants or organizations.
- Operators remain responsible for configuring workload identity within their own environment.

### 5.4 Hardware Security Modules and HSM‑Backed Keys

- While NonSudo can sign receipts using keys stored in an HSM, v1.1 does **not** require:
  - HSM-backed keys for signing receipts.
  - Hardware-based attestation for proxy binaries.
- These may be added as optional hardening in later versions.

### 5.5 Full Formal Verification and Static Non‑Interference Proofs

- Run mode v1.1 does not ship:
  - A formal proof that all code paths obey the policy.
  - A static guarantee that no data can flow from agent to upstream outside the proxy.
- Instead, it relies on:
  - Code review, testing, and conformance suites for receipts.
  - Identity + egress controls that can be independently audited.

### 5.6 Automatic Rollback or Self‑Healing

- Run mode does not:
  - Automatically roll back policy changes that degrade availability.
  - Self-heal misconfigured egress or identity.
- Those behaviors belong to higher-level orchestration and release-management systems.

---

## 6. What SREs Should Decide Before Enabling Run Mode

Before setting `mode: run` in production, SREs SHOULD:

- Decide which upstreams are **in-scope for non-bypassable enforcement** and confirm:
  - Agent workloads lack direct credentials to those upstreams.
  - Only the NonSudo proxy’s workload identity can reach them.
  - Egress policies for agent workloads enforce “proxy-only” routing.
- Define:
  - Availability SLOs and error budgets for the proxy.
  - Escalation paths when Run-mode invariants (e.g., budget enforcement, post-receipts) are violated.
- Document:
  - Which controls are enforced by NonSudo vs. surrounding infrastructure.
  - What auditors and internal reviewers should (and should not) infer from seeing `mode: run` in a manifest.

If these decisions and controls are not yet in place, NonSudo SHOULD remain in Walk mode until they are.

