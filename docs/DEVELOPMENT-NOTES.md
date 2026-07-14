# Development notes & roadmap

Handoff notes for this fork of [ScoutSuite](https://github.com/nccgroup/ScoutSuite)
(based on release `5.14.0`). Read this first when resuming work.

## What this fork adds

### Azure / Entra ID privilege-escalation checks
See [`entra-privesc-checks.md`](entra-privesc-checks.md) for the full write-up. Thirteen findings,
all wired into `providers/azure/rules/rulesets/default.json`:

| Finding file (in `providers/azure/rules/findings/`) | Level |
|---|---|
| `aad-app-registration-owner-weaker-than-permissions` | danger |
| `aad-app-registration-owner-escalates-to-subscription` | danger |
| `aad-service-principal-owner-weaker-than-permissions` | danger |
| `aad-service-principal-dangerous-permission-combination` | danger |
| `aad-app-federated-credential-broad` | danger |
| `aad-guest-user-strong-role` | danger |
| `aad-user-strong-subscription-but-weak-directory` | danger |
| `rbac-standing-privileged-subscription-role-assignment` (Azure RBAC, not Graph - grouped per subscription like Roles, own new resource/partial) | danger |
| `rbac-high-privilege-custom-role` (Azure RBAC, not Graph - reuses the existing Roles dashboard/partial, no new table) | danger |
| `aad-enterprise-app-strong-subscription-role` | warning |
| `aad-managed-identity-strong-subscription-role` | warning |
| `rbac-resource-provider-wildcard-custom-role` (Azure RBAC, lower-severity companion to `rbac-high-privilege-custom-role`; e.g. `Microsoft.Compute/*`) | warning |

The Roles drill-down (`ScoutSuite/output/data/html/partials/azure/services.rbac.subscriptions.id.roles.html`) - the
UPSTREAM partial these two RBAC findings reuse, shared with every built-in role too - was extended
with two always-visible lines: **Subscription** (resolves `@../key`, the parent `{{#each}}`'s key,
via `getValueAt` to the subscription's display name + ID - needed because the same role definition
can legitimately appear under multiple subscriptions, e.g. one assignable at a Management Group
scope) and **Full Permissions (JSON)** (the raw `actions`/`notActions`/`dataActions` array via the
existing `jsonToString` helper, always visible rather than only inside the pre-existing collapsed
"Permissions" accordion). This is the one place in the fork that edits an existing upstream
partial rather than adding a new one - low risk (two additive lines, no existing markup removed)
but worth knowing about if diffing against upstream.

Key code:
- Fetching: `providers/azure/facade/aad.py` (owners, appRoleAssignments, oauth2 grants, directory
  roles, PIM eligibility schedules, federated identity credentials), `providers/azure/resources/aad/`
  (applications, serviceprincipals, directoryroles, roleeligibility, owners helper).
- Correlation: `providers/azure/entra_privesc.py` (all cross-resource logic), invoked from
  `AzureProvider.preprocessing()` → `_compute_entra_privesc_checks()` in `providers/azure/provider.py`.
- Curated data (heuristics, tune these): `providers/azure/data/entra_privesc/*.json`.
- Known real bugs fixed along the way (worth knowing about if debugging odd results):
  - Azure ARM's role-assignment API can report `principalType: 'Unknown'` for a genuine Service
    Principal - match by principal ID against fetched objects instead of trusting that field (see
    `compute_enterprise_app_subscription_privilege_table` / `compute_standing_privileged_subscription_assignments`).
  - `rbac-high-privilege-custom-role`'s scope check went through two iterations before landing on
    the current (correct) approach:
    1. An exact string match against the current `subscription_id`
       (`scope == f'/subscriptions/{subscription_id}'`) - too strict, silently missed real custom
       roles whose `assignable_scopes` didn't byte-for-byte match how `subscription_id` is
       captured elsewhere.
    2. A regex (`_SUBSCRIPTION_SCOPE_RE`) matching "is this scope *a* subscription" (any
       subscription, or tenant root `/`) - better, but still missed real custom roles delegated
       via a **Management Group** scope (e.g.
       `"assignableScopes": ["/providers/Microsoft.Management/managementGroups/<mg>"]`), a common
       Landing-Zone/delegated-governance pattern. A real customer role with `actions: ["*"]`
       scoped only at an MG was reported by the user as a false negative (0 results across all
       three custom-role findings, incl. upstream's own `rbac-custom-subscription-owner-role-not-
       allowed`, which has the identical blind spot via its `"subscriptions" in assignable_scope`
       substring check).
    3. **Fixed by removing the scope-string check entirely.** Roles are fetched per subscription
       via `role_definitions.list(scope=f'/subscriptions/{subscription_id}')`, and Azure's own API
       only returns a role there if it's assignable at that subscription OR at any ancestor scope
       (parent/grandparent management group, or tenant root) - i.e. Azure has *already* resolved
       scope inheritance by the time a role shows up under a subscription's `roles` dict. Trying to
       re-derive "is this scope a subscription" from the raw `assignable_scopes` strings was both
       redundant (when correct) and incomplete (whenever Azure returns a scope shape - like an MG
       path - the regex didn't anticipate). `compute_high_privilege_custom_roles` now only checks
       `role_type == 'CustomRole'` + `is_subscription_role_strong()`/`_role_has_resource_provider_
       wildcard()`; presence in that subscription's `roles` dict already proves reachability.
  - **The same over-filtering existed in three functions that check ROLE ASSIGNMENTS rather than
    role definitions**, and "fixing" it took TWO iterations - the first was itself wrong.
    `compute_enterprise_app_subscription_privilege_table`, `_principals_with_strong_subscription_
    role`, and `compute_standing_privileged_subscription_assignments` all `continue`d (skipped) any
    assignment whose `scope` wasn't an exact string match for `/subscriptions/{subscription_id}`.
    That exact match excluded assignments inherited from an ancestor **management group** (the same
    Landing-Zone gap as the custom-role case) - a real Owner/UAA assignment made at an MG was
    invisible.

    **First (wrong) fix:** dropped the scope check ENTIRELY. This looked analogous to the
    role-definition fix but is NOT: `role_assignments.list_for_scope(scope='/subscriptions/{id}')`
    is called with **no `$filter`**, and that API returns assignments at the subscription, at every
    ancestor (MG/root), AND **at every DESCENDANT** (resource groups / resources beneath it). The
    role-definition List API does not return descendants, but the role-assignment one does. So
    dropping the check (a) over-reported - a role that only applies to one resource group was
    counted as subscription-wide - and (b) caused a real regression the user hit: a single
    descendant (resource-group-scoped) assignment that raised inside the loop (e.g. an unusual
    `role_definition_id`, or a role whose permissions structure tripped `is_subscription_role_
    strong`) would abort the whole `try` and **silently empty the Enterprise-Apps table finding**.
    Previously those descendant assignments were skipped by the exact-scope check before ever
    reaching the crashing line.

    **Second (correct) fix:** a shared predicate `_assignment_reaches_whole_subscription(assignment,
    subscription_id)` that excludes ONLY strict descendants (`scope` starts with
    `/subscriptions/{id}/`) while keeping the subscription itself and ancestor MG/root scopes. Plus
    per-assignment `try/except` in the two table-builders so one malformed assignment can never
    abort the whole table again, and `.get('role_definition_id')` instead of bracket access. This
    is a correctness fix in `_principals_with_strong_subscription_role` with a *security* edge: an
    owner who only holds a role on one resource group must NOT be treated as already having
    subscription access (which would suppress a legitimate owner-to-subscription escalation
    finding). Verified: subscription-scope and MG-ancestor assignments are picked up by all three
    functions; RG/resource-descendant assignments are excluded; a malformed descendant assignment
    is skipped without emptying the table; and the original `principalType:'Unknown'` UAA-at-
    subscription case still fires.
  - **Hardened the role-permission readers against the same silent-empty failure class.**
    `is_subscription_role_strong`, `is_role_granting_subscription_role`, and
    `_role_has_resource_provider_wildcard` iterated `permission.actions` (SDK object) /
    `permission.get('actions', [])` (dict) directly, which raises `TypeError: 'NoneType' object is
    not iterable` if a role has `actions: None`, a `None` permission block, or (for the dict form)
    an `actions` key present-but-None (`.get(k, [])` only defaults on a *missing* key). A single
    such role would abort `compute_high_privilege_custom_roles` (which had no per-role guard),
    silently emptying BOTH custom-role findings - the exact failure that had emptied the Enterprise
    Apps table. Fixed at the source with a shared `_role_action_strings(role_dict)` generator that
    coerces every level (`permissions`, each permission, its `actions`) to empty when None, so all
    three readers - and therefore every compute_* that calls them - are safe. Also added a per-role
    `try/except` in `compute_high_privilege_custom_roles`. Verified against roles with
    `actions:None`, a `None` permission, no `permissions` key, and an SDK-style object with
    `.actions=None`: none raise, and a good/RP-wildcard role alongside them is still flagged.
  - **Standing-privileged-assignments was originally a flat, cross-subscription table** under
    `aad.standing_privileged_subscription_role_assignments.id`. The user reported this as
    confusing in practice: the same principal holding a standing role on several subscriptions
    showed up as several visually identical rows ("Alice - Owner" repeated N times), distinguished
    only by a small `subscription_id` field visible in each row's detail panel - easy to miss.
    **Restructured** to mirror how the built-in Roles dashboard already presents equivalent data:
    `compute_standing_privileged_subscription_assignments` now builds a separate table PER
    subscription, stored directly on that subscription's own dict
    (`subscription['standing_privileged_role_assignments']`), so the finding's path moved to
    `rbac.subscriptions.id.standing_privileged_role_assignments.id` (was `aad.standing_privileged_
    subscription_role_assignments.id`) and the finding file was renamed `aad-standing-privileged-
    subscription-role-assignment.json` → `rbac-standing-privileged-subscription-role-assignment.
    json` to match the other `rbac-*` findings that already live under this path shape. Metadata,
    ruleset registration, and the HTML partial (moved + renamed to `services.rbac.subscriptions.
    id.standing_privileged_role_assignments.html`, `{{@../key}}`/`{{@key}}` conventions matching
    the Roles partial) were all updated to match. Verified end-to-end: the real ProcessingEngine
    fires one finding item per subscription (not collapsed into one), and the real Handlebars/
    helpers.js render each subscription's assignments as a separate, clearly-labelled group.
  - **The Applications/Service Principals drill-downs never rendered any of the fields this fork's
    checks compute.** `services.aad.applications.html` and `services.aad.service_principals.html`
    are unmodified upstream templates - they show basic object metadata (and, for SPs, Keys/
    Roles) but never `granted_permissions`, `owners_directory_roles`,
    `owner_weaker_than_app_permissions`, `federated_identity_credentials`/
    `broad_federated_credentials`, `dangerous_permission_combinations`,
    `owner_subscription_escalations`, or `strong_subscription_roles` - so a flagged app/SP showed
    the "danger" badge with no visible evidence of *why*. Added sections to both partials: Owners
    (with each owner's directory roles + tier, and a callout when `owner_weaker_than_app_
    permissions`), Granted Microsoft Graph Permissions (+ risk tier), Federated Identity
    Credentials (Applications only - every credential listed with issuer/subject and an "Overly
    Broad"/"Scoped" indicator per entry, not just the ones already flagged broad), Dangerous
    Permission Combinations (shown only `{{#if has_dangerous_permission_combination}}`), Owner Can
    Escalate to Subscription Control (Applications only, shown only `{{#if owner_escalates_to_
    subscription}}`), and Strong Subscription Roles (Service Principals only, shown only `{{#if
    has_strong_subscription_role}}`). `compute_broad_federated_credentials` now also sets `is_broad`
    directly on each entry of `federated_identity_credentials` (not just the separate
    `broad_federated_credentials` summary list), so the per-credential badge doesn't need to
    cross-reference two lists in Handlebars. Verified by rendering both partials through the real
    Handlebars/helpers.js with data exercising every conditional branch (weak owner, broad FIC,
    dangerous combo present/absent, subscription escalation, strong SP role) - all sections render
    with correct content and the conditional ones correctly appear/disappear.

### Azure network segregation checks
See [`network-segregation-checks.md`](network-segregation-checks.md) for the full write-up. Two
findings on `services.network.cross_subscription_vnet_peerings`:

| Finding file | Level |
|---|---|
| `network-cross-subscription-vnet-peering` | warning |
| `network-cross-environment-vnet-peering` (dev/test/prod mixing) | danger |

Key code: `providers/azure/network_segregation.py` (environment classification + cross-subscription
VNet Peering correlation), invoked from `AzureProvider.preprocessing()` →
`_compute_network_segregation_checks()`. VNet Peerings, previously fetched as unparsed raw SDK
objects nothing used, are now parsed in `resources/network/virtual_networks.py`. Subscription
`display_name`/`tags` (needed to classify environment) are captured in `resources/subscriptions.py`
- shared by every `Subscriptions`-based service, not just `network`. Curated environment-name
patterns: `providers/azure/data/network_segregation/environment_classification_patterns.json`.
Only native VNet Peering is covered (not VPN Gateway/ExpressRoute/vWAN) - documented v1 scope limit.

### AWS improvements
- **VPC-aware subnet flow-log check** (`AWSProvider._set_subnet_effective_flow_logs`):
  - `vpc-subnet-without-flow-log` (danger): neither subnet nor its VPC has a flow log.
  - `vpc-subnet-flow-log-only-at-vpc-level` (warning): covered only at VPC level (informational).
- **Unused internet-open security groups** (`AWSProvider._flag_unused_security_groups_with_open_ingress`):
  - `ec2-unused-security-group-with-open-ingress` (warning): SG open to 0.0.0.0/0/::/0 but not
    attached to anything. Additive — the existing `ec2-security-group-opens-*` (danger) findings
    are unchanged and still fire for these SGs too.

## How to test locally

There is no live cloud in the sandbox; verification is done against the real rule engine with
synthetic data. Pattern used throughout this work:

```bash
python3 -m venv /tmp/ss_venv
/tmp/ss_venv/bin/pip install -r requirements.txt pytest playwright

# byte-compile + JSON validation
python3 -m py_compile ScoutSuite/providers/<provider>/provider.py
python3 -c "import json; json.load(open('<finding>.json'))"

# upstream regression suite
/tmp/ss_venv/bin/python3 -m pytest tests/test_azure_provider.py tests/test_aws_provider.py \
  tests/test_rules_ruleset.py tests/test_rules_processingengine.py tests/test_main.py -q
```

**End-to-end finding test** (drive the real `ProcessingEngine`): build a stub provider with
`services` + `service_list`, run the preprocessing method(s), then
`ProcessingEngine(Ruleset(cloud_provider=..., filename='default.json')).run(stub, skip_dashboard=True)`
and assert on `stub.services[<svc>]['findings'][<finding-key>]['items']`. The finding key is the
JSON filename without `.json`.

**HTML render check** (confirm it appears like built-in findings): mix in `BaseProvider`'s
`_update_metadata` / `_update_last_run` / `recursive_get_count`, `ScoutReport(...).save(...)`, then
open `#services.<svc>.findings` in headless Chromium (`/opt/pw-browsers/chromium`) and assert the
description text is present. `textContent` (not `innerText`) sees collapsed accordion bodies.

## Adding a new correlation-based check (the pattern)

1. Fetch any missing data in the provider's `facade/` + `resources/`.
2. Compute a derived boolean/flag on the resource dict in a `preprocessing()` step (Azure:
   `entra_privesc.py`; AWS: a `_..._callback`/method in `provider.py`). The declarative JSON rule
   engine can only test one pre-flattened field per item — it cannot join across resource types.
3. Add a JSON finding under `rules/findings/` (`path` + a simple `true`/`equal` condition on the
   flag, plus `rationale`/`remediation`/`references`).
4. Register it in `rules/rulesets/default.json` with a `level` (`danger` or `warning` — those are
   the only two flagged severities the HTML report renders).

## Backlog / follow-ups (not yet done)

- **SG demote (optional):** make `ec2-security-group-opens-*` (danger) NOT fire for unused SGs, so
  the unused case is *only* the low-severity finding (true demote, like the subnet split). Touches
  ~8 CIS-mapped findings with deep `_INCLUDE_` conditions — test each. Currently additive instead.
- **RDS/Redshift `*-security-group-allows-all`** ignore `PubliclyAccessible`: a DB in a private
  subnet with no public endpoint is far lower risk. Data exists; cross-reference it (same pattern
  as the flow-log fix).
- **`s3-bucket-no-default-encryption`** predates AWS enabling SSE-S3 by default (Jan 2023); verify
  it no longer false-positives on buckets that are encrypted by the account/AWS default.
- **Multi-hop Entra escalation** (owner → group → nested group → role): real value but needs a
  graph engine, not the single-hop JSON rule model — architectural, out of scope for this fork.

## Performance / throttling (Azure AD fetch)

The Entra checks add per-object Graph calls. `msgraph-core==0.2.2`'s `GraphClient` is synchronous
(`requests`), so the facade runs each call in the thread-pool executor (`run_concurrently`) and the
`resources/aad/*` fetchers fan out per-object with `map_concurrently`. Built-in `Microsoft Services`
service principals are filtered out before the per-SP calls.

Throttling is **automatic — no `--max-rate` needed**. In `facade/aad.py`, `_graph_get`:
- caps concurrent Graph calls with a semaphore (`GRAPH_MAX_CONCURRENCY`, default 15, override via
  `SCOUT_AZURE_GRAPH_MAX_CONCURRENCY`), and
- retries HTTP 429 honouring the `Retry-After` header, so it self-throttles exactly as Graph asks.

If you still want a hard request-rate ceiling, `scout azure --max-rate <N>` feeds ScoutSuite's
loop throttler that `run_concurrently` already uses.

## Notes / gotchas

- Curated risk tiers (`data/entra_privesc/*.json`) and the tier constants in `entra_privesc.py`
  (`STRONG_GUEST_DIRECTORY_ROLE_TIER`, `WEAK_USER_DIRECTORY_ROLE_TIER`) are heuristics — tune per
  environment.
- Directory roles are matched by English display name; other Graph display languages fall back to
  the lowest tier.
- New Azure checks need extra read-only Graph permissions (see `entra-privesc-checks.md`); missing
  permissions fail gracefully (empty) rather than erroring the scan.
- Keep the fork rebased on upstream: `git fetch upstream && git merge <newer-tag>`; the added code
  is isolated to new files plus small, clearly-marked hooks in `provider.py`/`services.py`.
