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
| `aad-standing-privileged-subscription-role-assignment` | danger |
| `rbac-high-privilege-custom-role` (Azure RBAC, not Graph - reuses the existing Roles dashboard/partial, no new table) | danger |
| `aad-enterprise-app-strong-subscription-role` | warning |
| `aad-managed-identity-strong-subscription-role` | warning |
| `rbac-resource-provider-wildcard-custom-role` (Azure RBAC, lower-severity companion to `rbac-high-privilege-custom-role`; e.g. `Microsoft.Compute/*`) | warning |

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
  - A separate but analogous over-filtering exists in three functions that check ROLE
    **ASSIGNMENTS** rather than role definitions - `compute_enterprise_app_subscription_privilege_
    table`, `compute_standing_privileged_subscription_assignments`, and `_principals_with_strong_
    subscription_role` all `continue` (skip) any assignment whose `scope` isn't an exact string
    match for the current subscription. Azure's `role_assignments.list_for_scope()` (also called
    with no `$filter`) likely returns assignments made at the subscription itself *and* at any
    ancestor scope (management group/root), the same inheritance behavior as role definitions -
    which would mean a **standing** role assignment made at an MG (not literally at the
    subscription) is silently excluded by these three exact-match checks too. This is flagged but
    **not yet fixed** - unlike the role-definition case, naively dropping the scope filter here
    would collapse an MG-inherited assignment into a single table row (since the same assignment
    `id` recurs identically across every subscription under that MG, and the table dict is keyed
    by that `id`), losing the "which subscriptions does this reach" information; fixing it
    properly needs the row key to also incorporate `subscription_id`. Confirm with the user before
    changing this - it touches three functions and the correct fix needs more care than the
    role-definition case did.

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
