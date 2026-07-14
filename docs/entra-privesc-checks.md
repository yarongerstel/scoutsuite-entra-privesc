# Entra ID (Azure AD) privilege-escalation checks

This fork of [ScoutSuite](https://github.com/nccgroup/ScoutSuite) (based on release `5.14.0`)
adds Azure/Entra ID privilege-escalation checks that ScoutSuite's upstream Azure provider does
not have. All of them are ordinary ScoutSuite findings: they appear in the HTML report exactly
like the built-in checks (Danger/Warning severity, expandable rationale/remediation/references)
and are toggled in `rules/rulesets/default.json`.

1. **App Registration owner weaker than the app's granted permissions**
   (`aad-app-registration-owner-weaker-than-permissions`)
2. **Enterprise Application (Service Principal) with a strong role on a subscription**
   (`aad-enterprise-app-strong-subscription-role`), reported as a browsable table.
3. **Service Principal owner weaker than the SP's granted permissions**
   (`aad-service-principal-owner-weaker-than-permissions`)
4. **Service Principal holds a dangerous combination of Graph permissions**
   (`aad-service-principal-dangerous-permission-combination`)
5. **App Registration has an overly broad federated identity credential**
   (`aad-app-federated-credential-broad`)
6. **Guest user holds a strong directory or subscription role**
   (`aad-guest-user-strong-role`)
7. **User holds a strong subscription role despite being a weak directory identity**
   (`aad-user-strong-subscription-but-weak-directory`)
8. **Managed Identity holds a strong role on a subscription**
   (`aad-managed-identity-strong-subscription-role`)
9. **App Registration owner can escalate to subscription control**
   (`aad-app-registration-owner-escalates-to-subscription`)
10. **Standing privilege-escalation-capable subscription role assignment (baseline)**
    (`aad-standing-privileged-subscription-role-assignment`)
11. **Custom Azure RBAC role grants high privilege on a subscription**
    (`rbac-high-privilege-custom-role`) - not Entra/Graph-based like the others, but the same
    "strong subscription privilege" heuristic; see [below](#11-high-privilege-custom-rbac-roles).

Checks 1-2 are described in detail below; checks 3-11 are summarized in
[Additional checks](#additional-checks).

## 1. App Registration owner vs. granted permissions

For every **Application** (App Registration - i.e. *not* an Enterprise Application/Service
Principal), ScoutSuite now:

- Fetches the application's **owners** (`GET /applications/{id}/owners`).
- Fetches the Microsoft Graph **Application permissions actually granted** to the app's
  corresponding Service Principal (`GET /servicePrincipals/{id}/appRoleAssignments`) - this is
  what was actually consented/granted, as opposed to `requiredResourceAccess`, which only
  reflects what the app is configured to *request*.
- Fetches all activated **Entra directory roles and their members**
  (`GET /directoryRoles`, `GET /directoryRoles/{id}/members`).
- For each owner, looks up the highest-privilege directory role they hold (if any).
- Compares the highest **risk tier** of the app's granted Microsoft Graph permissions against
  the highest **privilege tier** of any owner's directory role.

If the granted-permission tier is strictly higher than every owner's directory-role tier, the
application is flagged: an owner can add a client secret/certificate to the app and authenticate
as it, inheriting the app's permissions - so an under-privileged owner can use an
over-permissioned app they own to escalate beyond their own assigned role.

This mirrors the well-documented Entra ID privilege-escalation pattern described by security
researchers (e.g. SpecterOps' write-ups on Azure AD/Entra privilege escalation via API
permission abuse).

### Risk tiering (curated, not authoritative)

- `ScoutSuite/providers/azure/data/entra_privesc/graph_application_permission_risk_tiers.json`
  tiers a **curated subset** of Microsoft Graph Application permissions with well-documented
  escalation potential (tier 4: e.g. `RoleManagement.ReadWrite.Directory`,
  `AppRoleAssignment.ReadWrite.All`, `Application.ReadWrite.All`, `Directory.ReadWrite.All`;
  tier 3: broad write permissions like `User.ReadWrite.All`, `Group.ReadWrite.All`; tier 1: broad
  read-only permissions). GUIDs were sourced from Microsoft's official
  [permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference).
  A granted permission whose GUID is **not** in this table is treated as tier 0 (not flagged) -
  this can under-report on permissions we haven't curated, but will never fabricate a match.
- `ScoutSuite/providers/azure/data/entra_privesc/directory_role_privilege_tiers.json` ranks
  built-in Entra directory roles by administrative power (Global Administrator highest, down to
  Helpdesk Administrator/read-only roles). Roles are matched by their **English `displayName`**
  as returned by Microsoft Graph; a tenant reporting role names in another display language will
  not match and will fall back to the lowest tier for that role.

Both tables are heuristics meant to catch common, well-known escalation paths - they are not an
exhaustive or Microsoft-endorsed classification. Treat findings as a prioritized starting point
for manual review, not a guarantee of exploitability (or of completeness).

## 2. Enterprise Applications with strong subscription roles

For every Service Principal (Enterprise Application) that holds an Azure RBAC role assignment
**directly at subscription scope** (not a narrower resource-group/resource scope), ScoutSuite now
classifies the role as "strong" if it is `Owner`, `Contributor`, `User Access Administrator`, or
any built-in/custom role whose actions include a wildcard-style grant (`*`,
`Microsoft.Authorization/*`, `.../roleAssignments/write`, `.../roleDefinitions/write`) - see
`ScoutSuite/providers/azure/data/entra_privesc/subscription_role_strength.json`.

Every such (Service Principal, subscription, role) combination is written into a new table,
`services.aad.enterprise_apps_with_strong_subscription_roles`, with columns:

| Column | Meaning |
|---|---|
| `name` | The Enterprise Application's display name |
| `app_id` | The application's `appId` |
| `subscription_id` | The subscription where the strong role is assigned |
| `role_name` | The RBAC role granted (e.g. `Owner`) |
| `owners` | The application's owners (see limitation below) |

### "Who created it" - a documented approximation

Microsoft Graph's `applications`/`servicePrincipals` APIs do not expose a `createdBy` field, so
there is no simple, generally-available API to answer "who created this app" directly. This check
uses the application's **owners** as a practical proxy for "who is responsible for/manages this
app" - owners are usually (but not always) the people who registered the app or were later
delegated its management. Getting the literal original creator would require Entra ID **Audit
Log** access (`AuditLog.Read.All` permission, plus sufficient log retention, i.e. querying
`auditLogs/directoryAudits` for an `Add application`/`Add service principal` event and correlating
its `initiatedBy`) - which is out of scope for this fork today, since audit log retention varies
by license and by tenant configuration and cannot be assumed to be reliably available or complete.

## Additional checks

All of the checks below reuse the same fetched data plus the curated risk-tier tables in
`ScoutSuite/providers/azure/data/entra_privesc/`. The correlation logic lives in
`ScoutSuite/providers/azure/entra_privesc.py` and runs in `AzureProvider.preprocessing()`.

### 3. Service Principal owner vs. granted permissions
The mirror of check 1, but for Service Principals (Enterprise Applications), which can have
their own owners distinct from the App Registration's. Flags an SP whose granted Microsoft
Graph Application permissions outrank the highest directory role held by any of its owners -
an owner can add credentials to the SP and act as it.

### 4. Dangerous permission combinations
Flags an app/SP whose granted Microsoft Graph permissions contain a full **combination** that
enables escalation even when each permission is not individually maximal - e.g.
`Application.ReadWrite.All` + `AppRoleAssignment.ReadWrite.All` (create/modify apps *and* grant
app roles = self-grant arbitrary permissions). The combinations are curated in
`dangerous_permission_combinations.json`; a combination matches only when **all** of its
permissions are present.

### 5. Overly broad federated identity credentials (Workload Identity Federation)
Fetches each application's federated identity credentials
(`GET /applications/{id}/federatedIdentityCredentials`) and flags any whose trusted subject is
overly broad - a wildcard, a GitHub Actions `pull_request` subject (exercisable by any PR,
including from forks), a subject not pinned to a specific branch/tag/environment, or a flexible
claims-matching expression. Anyone who can run in that external context can authenticate **as
the app** with no secret, inheriting its permissions. Issuer/subject heuristics are curated in
`broad_federated_credential_patterns.json`; a specific subject on an **unknown** issuer is not
flagged (conservative under-report).

### 6. Guest users holding strong roles
Flags a guest user (`userType == 'Guest'`) that holds a strong Entra directory role (tier >=
`STRONG_GUEST_DIRECTORY_ROLE_TIER`, default 2 = write-capable/admin) or a strong Azure RBAC role
at subscription scope. External accounts with standing admin power widen the tenant trust
boundary.

### 7. Users strong on a subscription but weak in the directory
Flags a user who holds a strong Azure RBAC role (Owner/Contributor/User Access
Administrator/wildcard) at subscription scope while being a **weak** directory identity - their
highest Entra directory role is at or below `WEAK_USER_DIRECTORY_ROLE_TIER` (default 1, i.e. no
admin role). These are ordinary, often less-protected accounts that nonetheless control a whole
subscription, concentrating blast radius on low-privileged users. Compromising one normal user
then yields subscription-level control.

### 10. Standing privilege-escalation-capable subscription role assignment (baseline)
`aad-standing-privileged-subscription-role-assignment` (danger). Unlike the other checks (which
are conditional/correlational), this is a **baseline least-privilege** check: it flags **every**
standing (active, non-PIM) role assignment at subscription scope of a role that can assign other
roles - Owner, User Access Administrator, RBAC Administrator, or a custom role with
`Microsoft.Authorization/roleAssignments/write` / wildcard - for **any** principal type (User,
Group, Service Principal, Managed Identity). This mirrors the "persistent User Access
Administrator / avoid standing high-privilege access" finding that tools like Prowler report, and
fills the gap the correlational checks leave (e.g. a User who holds User Access Administrator but
is *not* weak in the directory, so check 7 does not fire). Contributor is deliberately excluded
(it is "strong" but cannot assign roles). Principal type is resolved from the fetched directory
objects, so it is robust to Azure ARM reporting `principalType: 'Unknown'`.

### 9. App Registration owner can escalate to subscription control
`aad-app-registration-owner-escalates-to-subscription` (danger). The subscription/Azure-RBAC
counterpart to check 1. Flags an App Registration whose service principal holds a strong Azure
RBAC role at subscription scope when an owner does **not** already hold a strong role on that
subscription. The owner can add credentials to the app, authenticate as its service principal,
and gain subscription-level control (e.g. Owner/Contributor) they don't otherwise have - the exact
"owner has only directory permissions, escalates to a subscription via the app" path. An owner is
treated as already having the access if they hold a strong role **directly or through a group**
that holds it. Group resolution is best-effort, based on the group memberships ScoutSuite has
fetched; an owner whose membership wasn't fetched may still be flagged. Directory-role privilege
(used elsewhere) also counts PIM-**eligible** roles, not just active ones.

### 8. Managed Identities with strong subscription roles
Managed Identities are Service Principals (`servicePrincipalType == 'ManagedIdentity'`) whose
credentials Azure hands to a compute resource. A Managed Identity holding a strong subscription
role is surfaced as a distinct row/finding in the enterprise-app table (via the
`service_principal_type` column), because the escalation vector differs: whoever controls the
compute resource's control plane (or runs code on it) can obtain the identity's token from the
instance metadata endpoint and act with its subscription-level power.

### 11. High-privilege custom RBAC roles
`rbac-high-privilege-custom-role` (danger). Unlike the other checks, this is Azure RBAC
(`Microsoft.Authorization/roleDefinitions`), not Microsoft Graph/Entra - no new Graph permission
needed. Flags every **custom** role definition (`roleType == 'CustomRole'`) that is assignable at
subscription (or tenant root `/`) scope **and** grants Owner/Contributor/User Access
Administrator-equivalent permissions, using the same `is_subscription_role_strong()` heuristic as
the rest of this fork (curated in `data/entra_privesc/subscription_role_strength.json`). A custom
role assignable only at a narrower resource-group/resource scope is excluded even if its actions
are broad - Azure RBAC scope inheritance means it can't actually reach the whole subscription.

Custom roles are easy to create ad hoc and often escape the scrutiny given to built-in roles like
Owner - this surfaces the ones that are just as powerful. This check deliberately does **not**
introduce a new table/resource/HTML template: it sets `is_high_privilege_custom_role` directly on
ScoutSuite's existing `Roles` resource objects (`rbac.subscriptions.id.roles.id`), which already
render on the existing "Roles" dashboard/partial - including an **Assignments** section
(Users/Groups/Service Principals, resolved to display names, with a count badge) already
populated by upstream's `AzureProvider._match_rbac_roles_and_principals()`. That Assignments list
*is* "who/what is assigned to this role" - no new code needed to show it.

## Required Microsoft Graph permissions

In addition to what upstream ScoutSuite's Azure AD (`aad`) module already requires
(`Directory.Read.All` covers the existing `users`/`groups`/`servicePrincipals`/`applications`
reads), the new calls need read access to owners, app role assignments, and directory roles.
`Directory.Read.All` is sufficient for every row below **except the last one** (PIM eligibility -
see the warning underneath the table); narrower alternatives exist for the rest if you want to
scope credentials more tightly:

| New Graph call | Minimum permission |
|---|---|
| `GET /applications/{id}/owners` | `Application.Read.All` (or `Directory.Read.All`) |
| `GET /servicePrincipals/{id}/owners` | `Application.Read.All` (or `Directory.Read.All`) |
| `GET /servicePrincipals/{id}/appRoleAssignments` | `Application.Read.All` (or `Directory.Read.All`) |
| `GET /oauth2PermissionGrants?$filter=clientId eq ...` | `DelegatedPermissionGrant.Read.All` (or `Directory.Read.All`) |
| `GET /directoryRoles` and `.../members` | `RoleManagement.Read.Directory` (or `Directory.Read.All`) |
| `GET /applications/{id}/federatedIdentityCredentials` | `Application.Read.All` (or `Directory.Read.All`) |
| `GET /roleManagement/directory/roleEligibilityScheduleInstances` (PIM) | One of `RoleEligibilitySchedule.Read.Directory`, `RoleEligibilitySchedule.ReadWrite.Directory`, `RoleManagement.ReadWrite.Directory`, `RoleManagement.Read.Directory`, or `RoleManagement.Read.All`. **`Directory.Read.All` does NOT satisfy this call** (confirmed directly from Microsoft Graph's own `PermissionScopeNotGranted` error, which enumerates exactly this list) - it needs one of the RoleManagement/RoleEligibilitySchedule scopes specifically. |

> **PIM eligibility is optional and degrades gracefully.** The PIM row above is the one call in
> this fork that `Directory.Read.All` does not cover. Two separate things can block it:
> 1. **Delegated auth (`--cli`/`--user-account`) can't get this scope at all.** Azure CLI's own
>    first-party app registration has a fixed, Microsoft-defined set of Graph permissions it can
>    request; if none of the scopes above are in it (as observed - Azure CLI returns
>    `PermissionScopeNotGranted` for this call), no tenant-side admin consent can add it, because
>    you can only consent to a scope the client app has declared - and this isn't your app to edit.
>    The fix is to run with `--service-principal` (app-only, client-credentials) using your own App
>    Registration that has been granted the Microsoft Graph **Application** permission
>    `RoleManagement.Read.Directory` (or one of the others above) with admin consent.
> 2. **Even with the right scope, PIM itself requires an Entra ID P2 license** on the tenant - the
>    `roleManagement/directory/*` API is a P2 feature. Without P2 there are no eligible assignments
>    to read anyway, so falling back to active-only assignments is already the complete picture.
>
> Either way, if this call fails the scan logs a single informational line (with Graph's actual
> error message) and continues using **active** directory-role assignments only - nothing else is
> affected.

As with the rest of ScoutSuite's Azure AD module, these are **read-only** application permissions
granted to the service principal ScoutSuite authenticates as - running these checks does not
require, and does not use, any write permission.

## Running the checks

All the findings are enabled by default in `rules/rulesets/default.json`. Run as usual:

```bash
scout azure --cli  # or whatever auth method you use
```

To only see these checks, copy `default.json`, disable everything else, and pass it via
`--ruleset`:

```bash
scout azure --cli --ruleset my-entra-privesc-ruleset.json
```

## Known limitations

- Directory role matching is by English display name (see above).
- Graph permission risk tiering only covers a curated subset of permissions (see the JSON files
  in `ScoutSuite/providers/azure/data/entra_privesc/`); extend those tables if you rely on
  permissions not yet listed.
- "Owners" is used as a stand-in for "creator" (see above); it is not literally who created the
  application/service principal.
- The dangerous-combination and directory-tier thresholds are curated heuristics tuned to catch
  well-documented escalation paths; adjust the JSON tables and the tier constants in
  `entra_privesc.py` for your environment.
- Federated-credential breadth is a heuristic keyed on known CI issuers (GitHub/GitLab/Azure
  DevOps); a specific subject on an issuer not in `broad_federated_credential_patterns.json` is
  not flagged.
- All checks require the extra Graph permissions above; if ScoutSuite's credentials lack them,
  the corresponding calls fail gracefully (logged, returned empty) and the checks simply won't
  fire for that data rather than erroring out the whole scan.
