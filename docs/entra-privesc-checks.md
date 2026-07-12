# Entra ID (Azure AD) privilege-escalation checks

This fork of [ScoutSuite](https://github.com/nccgroup/ScoutSuite) (based on release `5.14.0`)
adds two Azure/Entra ID checks that ScoutSuite's upstream Azure provider does not have:

1. **App Registration owner weaker than the app's granted permissions**
   (`aad-app-registration-owner-weaker-than-permissions`)
2. **Enterprise Application (Service Principal) with a strong role on a subscription**
   (`aad-enterprise-app-strong-subscription-role`), reported as a browsable table.

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

## Required Microsoft Graph permissions

In addition to what upstream ScoutSuite's Azure AD (`aad`) module already requires
(`Directory.Read.All` covers the existing `users`/`groups`/`servicePrincipals`/`applications`
reads), the new calls need read access to owners, app role assignments, and directory roles.
`Directory.Read.All` alone is sufficient for everything below; narrower alternatives exist if you
want to scope credentials more tightly:

| New Graph call | Minimum permission |
|---|---|
| `GET /applications/{id}/owners` | `Application.Read.All` (or `Directory.Read.All`) |
| `GET /servicePrincipals/{id}/owners` | `Application.Read.All` (or `Directory.Read.All`) |
| `GET /servicePrincipals/{id}/appRoleAssignments` | `Application.Read.All` (or `Directory.Read.All`) |
| `GET /oauth2PermissionGrants?$filter=clientId eq ...` | `DelegatedPermissionGrant.Read.All` (or `Directory.Read.All`) |
| `GET /directoryRoles` and `.../members` | `RoleManagement.Read.Directory` (or `Directory.Read.All`) |

As with the rest of ScoutSuite's Azure AD module, these are **read-only** application permissions
granted to the service principal ScoutSuite authenticates as - running these checks does not
require, and does not use, any write permission.

## Running the checks

The two findings are enabled by default in `rules/rulesets/default.json`. Run as usual:

```bash
scout azure --cli  # or whatever auth method you use
```

To only see these two checks, copy `default.json`, disable everything else, and pass it via
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
- Both checks require the extra Graph permissions above; if ScoutSuite's credentials lack them,
  the corresponding calls fail gracefully (logged, returned empty) and the checks simply won't
  fire for that data rather than erroring out the whole scan.
