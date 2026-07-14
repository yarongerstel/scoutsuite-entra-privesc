# Session state — continuity document

**Purpose**: this file exists so that if the conversation/context window that built this fork is
lost, a fresh session (human or Claude) can reconstruct everything: what was built, why, what's
already tested, what's an open/pending decision, and exactly how to keep going. Read this FIRST,
then `DEVELOPMENT-NOTES.md` for the developer-facing "how the code fits together" reference.

Last updated at commit `b0e1f938` on branch `main` of `yarongerstel/scoutsuite-entra-privesc`
(a private fork of `nccgroup/ScoutSuite`, based on release `5.14.0`).

## Repo coordinates

- Remote: `https://github.com/yarongerstel/scoutsuite-entra-privesc` (private)
- Local clone in this environment: `/workspace/scoutsuite-entra-privesc`
- Fork base commit (where upstream ScoutSuite 5.14.0 ends and our changes begin):
  `507d5050` ("Merge ScoutSuite 5.14.0 ... as fork base")
- Working tree is clean as of this writing; every change described below is committed AND pushed
  to `origin/main`. There is nothing uncommitted waiting to be saved.

## What this session built, in order (see `git log` for full commit messages)

1. **Forked ScoutSuite** into this new repo (the user couldn't create the repo themselves via the
   GitHub App - a 403 permission gap - so the user created an empty repo manually and this
   session cloned upstream ScoutSuite's history into it).
2. **Entra ID / Azure AD privilege-escalation checks** (8 findings initially, grew to 10):
   owner-vs-permissions on App Registrations and Service Principals, dangerous Graph permission
   combinations, overly-broad federated identity credentials (Workload Identity Federation),
   guest users with strong roles, users strong-on-subscription-but-weak-in-directory, the
   enterprise-app/managed-identity strong-subscription-role table, app-owner-escalates-to-
   subscription, and a baseline standing-privileged-subscription-role-assignment check.
3. **AWS improvements**: made the VPC subnet flow-log check VPC-aware (a subnet covered only by a
   VPC-level flow log is no longer a false-positive danger, demoted to a separate low-severity
   finding), and added a low-severity finding for unused internet-open security groups.
4. **Performance**: parallelized the Azure AD Graph fetch (was fully sequential and blocking the
   event loop - msgraph-core 0.2.2 is synchronous) with a concurrency-capped, self-throttling
   (honors HTTP 429 Retry-After) executor-based fetch. Large speedup on tenants with many
   applications/service principals.
5. **PIM eligibility**: added fetching of PIM-eligible (not just active) directory role
   assignments, so a user eligible for e.g. Global Administrator is not misclassified as a "weak"
   identity. Gracefully degrades (info-level log, not error) when the run doesn't have
   `RoleManagement.Read.Directory`/P2 - see the "real bugs found" section below for the precise
   diagnosis of why this specific call fails in the user's environment (Azure CLI's own delegated
   auth scope, not a license/consent issue that can be fixed on the tenant side).
6. **Azure network segregation checks** (new domain, separate from Entra): cross-subscription VNet
   Peering (baseline, warning) and cross-environment dev/test/prod VNet Peering (danger), with a
   curated, tunable environment-classification heuristic based on subscription display name/tags.
7. **High-privilege custom RBAC role check**: finds `Microsoft.Authorization/roleDefinitions`
   custom roles assignable at subscription scope that grant Owner/Contributor/User Access
   Administrator-equivalent permissions, and shows who's assigned to them - by reusing
   ScoutSuite's *existing* Roles dashboard/HTML partial rather than building new UI.

## Real bugs found and fixed along the way (not just features - genuine correctness fixes)

These are worth knowing about because they reveal real Azure API quirks that could bite future
checks too:

1. **Azure ARM's role-assignment API can report `principalType: 'Unknown'`** for a genuine
   Service Principal (a documented ARM quirk - its own internal AAD lookup doesn't always
   resolve at read time). A check that filters `assignment.principal_type == 'ServicePrincipal'`
   will silently miss real SP-held roles. Fix: match by principal ID against already-fetched
   objects instead of trusting that field - the same pattern upstream's own
   `AzureProvider._match_rbac_roles_and_principals()` already used (it never checks
   `principal_type` at all, for exactly this reason). Found via the user cross-checking against
   Prowler, which caught an SP ScoutSuite had missed.
2. **Pattern-matching a custom role's `assignable_scopes` string is inherently incomplete - fixed
   by not doing it at all.** Two iterations: (a) an exact-string match
   (`scope == f'/subscriptions/{subscription_id}'`) silently missed real custom roles at
   subscription scope with non-matching casing/format; (b) a regex
   (`^/subscriptions/[^/]+/?$`, "is this scope *a* subscription") fixed that, but still missed a
   real user-reported role delegated purely via a **Management Group** scope
   (`"assignableScopes": ["/providers/Microsoft.Management/managementGroups/<mg>"]` - a common
   Landing-Zone/delegated-governance pattern), reported as a false negative (0 results across all
   three custom-role findings, including upstream's own pre-existing
   `rbac-custom-subscription-owner-role-not-allowed`, which has the identical blind spot via its
   `"subscriptions" in assignable_scope` substring check - not fixed, since it's unmodified
   upstream code, but documented). **Root fix:** removed the scope-string check entirely. Roles
   are fetched per subscription via
   `role_definitions.list(scope=f'/subscriptions/{subscription_id}')`, and Azure's own API only
   returns a role there if it's assignable at that subscription *or any ancestor scope* - Azure has
   already resolved scope inheritance by the time a role shows up under a subscription's `roles`
   dict, so re-deriving "is this scope a subscription" from the raw strings was both redundant and
   incomplete (it can only miss scope shapes it didn't anticipate, like MG paths).
   `compute_high_privilege_custom_roles` now only checks `role_type == 'CustomRole'` +
   `is_subscription_role_strong()` / `_role_has_resource_provider_wildcard()`.
   **Related, NOT yet fixed:** three functions that check role *assignments* rather than role
   *definitions* (`compute_enterprise_app_subscription_privilege_table`,
   `compute_standing_privileged_subscription_assignments`, `_principals_with_strong_subscription_
   role`) have the same exact-scope-match pattern on `assignment.get('scope')`, which likely has
   the identical Management-Group blind spot for **standing role assignments** made at an MG rather
   than literally at the subscription. Not fixed yet because naively dropping that filter would
   collapse an MG-inherited assignment into a single table row (it recurs with the same assignment
   `id` under every subscription in that MG, and the table is keyed by `id`) - needs the row key to
   also incorporate `subscription_id`. Ask the user before touching this - it's a bigger, three-
   function change.
3. **Custom "flat table" findings render as a BLANK page without three specific things**: (a) the
   metadata.json `cols` value is a RENDER MODE (0/1/2 only - `loadConfig()` in the report's JS has
   no branch for `cols >= 3`, so setting `cols: 4` silently renders nothing), not a column count;
   (b) a matching `<resource>_count` key in the provider (the report only paginates/loads a
   resource that has one); (c) a Handlebars partial template under
   `ScoutSuite/output/data/html/partials/azure/`. Missing any of these produces a finding that
   fires correctly (shows in the findings list with the right severity) but whose drill-down page
   is completely empty. Found when the user reported "no content" on the standing-privileged
   finding's detail page; fixed for both that table and the earlier
   `enterprise_apps_with_strong_subscription_roles` table, which had been silently broken the
   same way since it was first added.
4. **PIM eligibility read (`roleManagement/directory/roleEligibilityScheduleInstances`) needs a
   specific scope set that `Directory.Read.All` does NOT satisfy** - confirmed directly from
   Microsoft Graph's own `PermissionScopeNotGranted` error body, which enumerates the actual
   accepted scopes (`RoleEligibilitySchedule.Read.Directory` / `RoleManagement.Read.Directory` /
   `RoleManagement.Read.All` / etc.) None of upstream ScoutSuite's own docs claimed this endpoint
   needed anything beyond `Directory.Read.All`; this fork's docs originally repeated that
   incorrect assumption and were corrected once the live error proved otherwise. Separately:
   Azure CLI's own first-party app registration has a fixed, Microsoft-defined Graph permission
   set that doesn't include this scope at all for delegated (`--cli`) auth - no amount of tenant
   admin consent can add it, since you can only consent to a scope the client app has declared.
   The fix path (if the user wants this data) is running with `--service-principal` against a
   dedicated App Registration granted the Application permission with admin consent.

## Open / pending decision (unresolved as of this writing)

The user asked (last message before this summary was requested) whether **other custom roles will
also be detected**, not just the two exact ones they reported. I tested this and reported back
with concrete results - **this is answered, not blocking** - but it surfaced a genuine, still-open
design question the user has not yet answered:

**Current behavior** (`is_subscription_role_strong()` in `entra_privesc.py`, shared by every
"strong subscription role" check in this fork): only catches a **literal** wildcard `"*"` action,
or a Microsoft.Authorization-specific wildcard/write action (`Microsoft.Authorization/*`,
`.../roleAssignments/write`, `.../roleDefinitions/write`). Case-insensitive, checks every
permission block on the role, works regardless of what's excluded via `notActions`.

**What is NOT caught** (verified, not a bug - a scope boundary of the current heuristic):
- Resource-provider-wide wildcards that are not the bare `"*"` - e.g. a custom role with
  `["Microsoft.Compute/*", "Microsoft.Storage/*"]` and nothing else. Broad within those RPs, but
  not Owner/Contributor-equivalent (can't touch IAM, Network, etc.), so currently excluded by
  design/consistency with every other "strong" check in this fork.
- `"*/read"` + `"*/write"` style dual-wildcard patterns (not a bare `"*"`).
- Roles assignable only via a Management Group scope (no MG hierarchy data is fetched at all -
  documented gap, distinct from the two above).

**RESOLVED - the user chose option 2 (add a lower-severity finding).** Implemented as
`rbac-resource-provider-wildcard-custom-role` (warning): a custom role assignable at subscription
(or root) scope whose actions include a single-resource-provider wildcard (`<namespace>/*`, e.g.
`Microsoft.Compute/*`) but is NOT already flagged high-privilege (danger). Computed in the same
pass by `compute_high_privilege_custom_roles`, which now sets two flags -
`is_high_privilege_custom_role` (danger) and `is_resource_provider_wildcard_custom_role` (warning)
- and excludes any already-high-privilege role from the warning tier so each role is reported at
exactly one severity. `is_subscription_role_strong()` itself was left unchanged (the danger bar is
still only true Owner-equivalent power); the new tier is additive. Detection: `_role_has_resource_
provider_wildcard()` + `_RESOURCE_PROVIDER_WILDCARD_RE` (`^<namespace>/*$`). Reuses the existing
Roles dashboard/partial - no new table. Still NOT caught (unchanged, documented gaps): `*/read` +
`*/write` dual-wildcard patterns, and Management-Group-only assignable scopes.

## Testing setup (must be recreated in a fresh environment/session)

There is no live Azure tenant available in this sandbox. Everything was verified via:

1. **A local venv with ScoutSuite's dependencies installed** (not committed to the repo - recreate
   it):
   ```bash
   python3 -m venv /tmp/ss_venv
   /tmp/ss_venv/bin/pip install -r requirements.txt pytest playwright
   ```
2. **Byte-compile + JSON validation** after any change:
   ```bash
   python3 -m py_compile ScoutSuite/providers/azure/<changed_file>.py
   python3 -c "import json; json.load(open('<changed_finding_or_ruleset>.json'))"
   ```
3. **Upstream regression suite**:
   ```bash
   /tmp/ss_venv/bin/python3 -m pytest tests/ -q --ignore=tests/test_scoutsuite.py
   ```
   (`test_scoutsuite.py`'s `test_scout_suite_help` fails in THIS sandbox only because it shells
   out via `#!/usr/bin/env python3`, which resolves to the system interpreter that doesn't have
   the venv's dependencies installed - confirmed unrelated to any code change here by running
   `scout.py --help` directly with the venv's interpreter, which works. Not a real regression;
   re-verify this reasoning still holds if the sandbox environment changes.)
4. **Synthetic unit tests** for every new correlation function - build a small dict of fake
   resource data reflecting the exact edge case being tested, call the `compute_*`/`is_*` function
   directly, assert on the derived flags. See any commit message in `git log` for a concrete
   example inline.
5. **Real rule-engine test** - construct a minimal stub object with `.services`/`.service_list`,
   run `ProcessingEngine(Ruleset(cloud_provider='azure', filename='default.json')).run(stub,
   skip_dashboard=True)`, assert on `stub.services[<svc>]['findings'][<finding-key>]['items']`.
6. **Full HTML report render in headless Chromium** (`/opt/pw-browsers/chromium`, pre-installed in
   this environment) - build a fuller stub provider, wire in `BaseProvider._update_metadata` /
   `_update_last_run` / `recursive_get_count`, call `ScoutReport(...).save(...)`, then open
   `#services.<svc>.findings` (dashboard) and
   `#services.<svc>.findings.<finding-key>.items` (drill-down) with Playwright and assert the
   expected text/fields are present. **This step is what caught bug #3 above** (blank drill-down) -
   the dashboard alone would NOT have revealed it, since the finding still shows correctly in the
   summary list even when its drill-down is broken. Always check both.

## Where everything lives (quick file map)

- `docs/entra-privesc-checks.md` - full write-up of all Entra/Graph + RBAC subscription checks.
- `docs/network-segregation-checks.md` - full write-up of the VNet peering checks.
- `docs/DEVELOPMENT-NOTES.md` - developer-facing architecture reference, the "add a new check"
  pattern, and a longer-running backlog list (the RP-wide wildcard question above is now RESOLVED
  and shipped as `rbac-resource-provider-wildcard-custom-role`).
- `ScoutSuite/providers/azure/entra_privesc.py` - almost all Entra + RBAC-subscription-strength
  correlation logic (yes, including the RBAC custom-role check - kept there for consistency, since
  it reuses `is_subscription_role_strong()` from the same module).
- `ScoutSuite/providers/azure/network_segregation.py` - VNet peering / environment classification
  (kept separate - genuinely different domain, networking vs identity/RBAC).
- `ScoutSuite/providers/azure/data/entra_privesc/*.json` and
  `ScoutSuite/providers/azure/data/network_segregation/*.json` - every curated heuristic
  (permission risk tiers, directory role tiers, subscription role strength, dangerous permission
  combinations, federated credential patterns, environment classification patterns). Tune these
  before touching Python code if a check is too noisy or too quiet for a given tenant's
  conventions.
- `ScoutSuite/providers/azure/provider.py` - `_compute_entra_privesc_checks()` and
  `_compute_network_segregation_checks()`, both called from `preprocessing()`. This is the wiring
  point for every new check - read it top to bottom to see the full call graph and ordering
  dependencies (several `compute_*` functions must run after others that populate fields they
  read - comments at each call site say which).

## How to resume in one paragraph

`git pull` on `main` in `/workspace/scoutsuite-entra-privesc` (or re-clone
`yarongerstel/scoutsuite-entra-privesc`), recreate the venv (command above), read this file plus
`DEVELOPMENT-NOTES.md`. There are no open decisions - the RP-wide-wildcard question was resolved
(the user chose the lower-severity finding) and shipped. Everything described here is finished,
tested, and already pushed.
