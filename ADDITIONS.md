# Fork additions — full catalogue

This fork of [nccgroup/ScoutSuite](https://github.com/nccgroup/ScoutSuite) (based on release
`5.14.0`) adds **17 custom security findings** on top of upstream: 14 Azure / Entra ID
privilege-escalation & network-segregation checks and 3 AWS check improvements. Every finding is
additive — no upstream check was removed or weakened — and each one renders in the HTML report
exactly like a built-in finding, with its own problem statement, escalation/impact rationale, and
remediation steps.

This page is the index. Deep-dives live in:
- [`docs/entra-privesc-checks.md`](docs/entra-privesc-checks.md) — Azure/Entra + RBAC checks
- [`docs/network-segregation-checks.md`](docs/network-segregation-checks.md) — VNet peering checks
- [`docs/DEVELOPMENT-NOTES.md`](docs/DEVELOPMENT-NOTES.md) — architecture, "add a new check" pattern, backlog
- [`docs/SESSION-STATE.md`](docs/SESSION-STATE.md) — continuity snapshot (bugs found/fixed, decisions)

Severity legend: **danger** = high-confidence privilege-escalation / segregation break;
**warning** = broad standing access or baseline hygiene worth reviewing. (Those are the only two
severities ScoutSuite renders as flagged.)

---

## Azure — Entra ID (Azure AD) privilege-escalation checks

These correlate data the upstream Azure provider never joined: application/service-principal
**owners**, granted **Microsoft Graph application permissions**, **directory roles** (including
**PIM-eligible** roles), **federated identity credentials**, and **Azure RBAC role assignments** at
subscription scope. Correlation logic lives in
[`ScoutSuite/providers/azure/entra_privesc.py`](ScoutSuite/providers/azure/entra_privesc.py);
curated risk heuristics are in `ScoutSuite/providers/azure/data/entra_privesc/*.json` (tune per
tenant).

| # | Finding | Severity | What it detects |
|---|---------|----------|-----------------|
| 1 | `aad-app-registration-owner-weaker-than-permissions` | danger | An **App Registration owner** whose own directory role is *weaker* than the Graph permissions the app grants — owning the app is an escalation path to those permissions. |
| 2 | `aad-app-registration-owner-escalates-to-subscription` | danger | An app owner who does **not** already hold a strong role on a subscription, but whose app's service principal does — the owner can add credentials, authenticate as the SP, and seize subscription control (incl. via **group-transitive** access). |
| 3 | `aad-service-principal-owner-weaker-than-permissions` | danger | Same owner-vs-permissions gap as #1, for **Enterprise Applications (Service Principals)** that carry their own owners and permissions. |
| 4 | `aad-service-principal-dangerous-permission-combination` | danger | A single app/SP holding a **dangerous *combination*** of Graph permissions (e.g. `AppRoleAssignment.ReadWrite.All` + `Application.ReadWrite.All`) that together enable tenant takeover, even if no single one looks alarming. |
| 5 | `aad-app-federated-credential-broad` | danger | An **overly-broad federated identity credential** (Workload Identity Federation) — wildcard subject, flexible-claims matching, or a CI issuer not pinned to a specific branch/tag/environment — that lets outside workloads mint tokens as the app. |
| 6 | `aad-guest-user-strong-role` | danger | A **guest** (`userType == Guest`) holding a strong directory role (active or PIM-eligible) or a strong Azure RBAC role on a subscription. |
| 7 | `aad-user-strong-subscription-but-weak-directory` | danger | A user who is **weak in the directory** (no admin role, active or PIM-eligible) yet holds a **strong Azure RBAC role** on a subscription — concentrated control-plane blast radius on an ordinary account. |
| 8 | `aad-enterprise-app-strong-subscription-role` | warning | Table of every **Enterprise Application** holding a strong Azure RBAC role directly at subscription scope — which permission, and its owners (creator approximation). |
| 9 | `aad-managed-identity-strong-subscription-role` | warning | Subset of #8 called out separately: a **Managed Identity** with a strong subscription role — a distinct control-plane escalation vector (token available from instance metadata). |

## Azure — RBAC checks

Pure Azure RBAC (`Microsoft.Authorization/roleDefinitions` / role assignments), no Graph
permission needed. #10/#11 reuse ScoutSuite's **existing Roles dashboard/partial** — including the
**Assignments** section (who/what holds the role, resolved to display names) — so no new table or
template is introduced. #12 has its own new resource, grouped per subscription the same way the
built-in Roles dashboard already is.

| # | Finding | Severity | What it detects |
|---|---------|----------|-----------------|
| 10 | `rbac-high-privilege-custom-role` | danger | A **custom** role, assignable at subscription (or tenant root) scope, granting Owner/Contributor/User Access Administrator-equivalent power — a `*` wildcard, `Microsoft.Authorization/*`, or role-assignment/definition write. |
| 11 | `rbac-resource-provider-wildcard-custom-role` | warning | Lower-severity companion to #10: a custom role granting a **single resource-provider wildcard** (e.g. `Microsoft.Compute/*`) — broad control of one whole provider, narrower than full Owner. A role is reported at **exactly one** severity, never both. |
| 12 | `rbac-standing-privileged-subscription-role-assignment` | danger | Baseline least-privilege check: every **standing (always-active, non-PIM)** role assignment at subscription scope of a role that can assign other roles (Owner / User Access Administrator / RBAC Administrator / custom role with `roleAssignments/write`), for **any** principal type. Grouped per subscription — the same principal on N subscriptions shows as N separate, clearly-labelled rows instead of one flat table of look-alike entries. |

## Azure — network segregation checks

Flags cross-boundary network reachability via **VNet Peering** (Azure's equivalent of a shared
VLAN / cross-network link). Logic in
[`ScoutSuite/providers/azure/network_segregation.py`](ScoutSuite/providers/azure/network_segregation.py);
environment name/tag patterns in `data/network_segregation/environment_classification_patterns.json`.

| # | Finding | Severity | What it detects |
|---|---------|----------|-----------------|
| 13 | `network-cross-subscription-vnet-peering` | warning | Any **connected VNet peering that crosses a subscription boundary** — baseline visibility (common and often legitimate in hub-spoke). |
| 14 | `network-cross-environment-vnet-peering` | danger | A peering that connects two subscriptions classified into **different environments** (e.g. production ↔ development/test) — the actual dev/test/prod segregation break. |

## AWS — check improvements

| # | Finding | Severity | What it detects |
|---|---------|----------|-----------------|
| 15 | `vpc-subnet-without-flow-log` | danger | A subnet with **no flow log**, made **VPC-aware**: only flagged when *neither* the subnet *nor its parent VPC* has a flow log (fixes a false positive where VPC-level coverage was ignored). |
| 16 | `vpc-subnet-flow-log-only-at-vpc-level` | warning | Informational split of #15: the subnet is covered **only** at the VPC level — visible, but not a real gap. |
| 17 | `ec2-unused-security-group-with-open-ingress` | warning | A security group open to `0.0.0.0/0` / `::/0` that is **not attached to anything**. Additive — the existing `ec2-security-group-opens-*` (danger) findings are unchanged. |

---

## Notable correctness work

Real bugs found and fixed while building these (details in `docs/SESSION-STATE.md`):

- **PIM-eligible admin mistaken for weak identity** — the directory-role tier now counts both
  active `/directoryRoles` members *and* PIM `roleEligibilityScheduleInstances`, so a user merely
  *eligible* to activate Global Administrator is not flagged as a weak identity (#7).
- **ARM `principalType: 'Unknown'`** — role assignments are matched by **principal ID** against the
  fetched directory objects, not by trusting Azure's reported type, so a genuine Service Principal
  with e.g. User Access Administrator is not silently missed (#8, #9).
- **Custom-role scope match too strict** — an exact `scope == /subscriptions/<id>` string match
  silently missed real custom roles; replaced with a regex that answers "is this scope *a*
  subscription" while still excluding resource-group/resource scopes (#11).

## Performance / throttling

The Entra checks add per-object Microsoft Graph calls. Fetching is **parallelised** (thread-pool
executor + per-object fan-out) and throttling is **automatic — no `--max-rate` needed**: a
semaphore caps concurrent Graph calls and HTTP 429s are retried honouring `Retry-After`. See the
Performance section of `docs/DEVELOPMENT-NOTES.md`.

## Required extra permissions

The new Azure checks need read-only Graph/directory permissions beyond upstream's set (owners,
app-role assignments, directory roles, PIM eligibility schedules, federated credentials). Missing
permissions **fail gracefully** (that check returns empty) rather than aborting the scan. The exact
list is in the "Required Microsoft Graph permissions" section of `docs/entra-privesc-checks.md`.
