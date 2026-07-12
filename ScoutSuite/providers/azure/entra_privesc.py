"""
Cross-resource correlation for two Entra ID (Azure AD) privilege-escalation checks that
cannot be expressed as a single-resource JMESPath rule:

1. App Registration (Application) owner privilege check: flags an Application when the
   Application Permissions (API permissions) granted to its corresponding Service Principal
   outrank the highest Entra directory role held by any of the Application's owners. An
   owner can add credentials/secrets to the app and act as it, so an owner who is weaker
   than their own app's permissions can use the app to escalate their own privilege.

2. Enterprise Application (Service Principal) subscription privilege table: for each
   Service Principal holding a 'strong' Azure RBAC role at subscription scope, records
   which role(s)/subscription(s) it holds and who owns/created it.

Both derived results are written back onto the relevant resource dicts (following the same
pattern as AzureProvider._match_rbac_roles_and_principals) so that simple declarative JSON
rules can flag them.

IMPORTANT / LIMITATIONS (see docs/entra-privesc-checks.md for the full write-up):
 - The permission and directory-role risk tiers below are a curated, opinionated heuristic,
   not an authoritative Microsoft ranking. They are meant to catch the common/well-documented
   privilege-escalation-enabling permissions, not to be an exhaustive classification of all
   Microsoft Graph permissions or all built-in directory roles.
 - Directory roles are matched by their English displayName as returned by Microsoft Graph;
   tenants using a different Graph-reported display language will not match and fall back to
   the lowest tier.
 - Microsoft Graph API permissions are matched by GUID (appRoleId) against a curated table of
   well-known Microsoft Graph Application permission GUIDs. An appRoleAssignment granted from
   a resource other than Microsoft Graph, or a Microsoft Graph permission not present in the
   curated table, cannot be tiered and is treated as tier 0 (NOT flagged) rather than guessed -
   this can under-report risk for permissions we haven't curated, it will never over-report.
 - "Who created" an Enterprise Application is approximated via its owners, because Microsoft
   Graph's `applications`/`servicePrincipals` APIs do not expose a `createdBy` field; the true
   creator would require Entra ID Audit Log access (`AuditLog.Read.All` + log retention), which
   this check does not attempt.
"""

import json
import os

from ScoutSuite.core.console import print_exception

_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'entra_privesc')

MICROSOFT_GRAPH_APP_ID = '00000003-0000-0000-c000-000000000000'


def _load_json(filename):
    path = os.path.join(_DATA_DIR, filename)
    with open(path, 'r') as f:
        return json.load(f)


_directory_role_tiers_data = _load_json('directory_role_privilege_tiers.json')
_graph_permission_tiers_data = _load_json('graph_application_permission_risk_tiers.json')
_subscription_role_strength_data = _load_json('subscription_role_strength.json')

# name (lowercased) -> tier (int)
_DIRECTORY_ROLE_NAME_TO_TIER = {
    name.lower(): int(tier)
    for tier, names in _directory_role_tiers_data['tiers'].items()
    for name in names
}
_DIRECTORY_ROLE_DEFAULT_TIER = _directory_role_tiers_data['default_tier']

# appRoleId (lowercased GUID) -> {'name': str, 'tier': int}
_GRAPH_PERMISSION_ID_TO_INFO = {
    app_role_id.lower(): {'name': info['name'], 'tier': info['tier']}
    for app_role_id, info in _graph_permission_tiers_data['permissions'].items()
}

_STRONG_BUILT_IN_ROLE_NAMES = {
    name.lower() for name in _subscription_role_strength_data['strong_built_in_role_names']
}
_STRONG_ACTION_PATTERNS = [
    pattern.lower() for pattern in _subscription_role_strength_data['strong_action_patterns']
]


def get_directory_role_tier(role_display_name):
    if not role_display_name:
        return _DIRECTORY_ROLE_DEFAULT_TIER
    return _DIRECTORY_ROLE_NAME_TO_TIER.get(role_display_name.lower(), _DIRECTORY_ROLE_DEFAULT_TIER)


def get_graph_permission_info(app_role_id):
    if not app_role_id:
        return None
    return _GRAPH_PERMISSION_ID_TO_INFO.get(app_role_id.lower())


def is_subscription_role_strong(role_dict):
    """
    A subscription-scope RBAC role is considered 'strong' if it's one of the well-known
    high-privilege built-ins (Owner/Contributor/User Access Administrator), it was already
    flagged by ScoutSuite as a wildcard custom role (`custom_subscription_owner_role`), or
    any of its actions match a known broad/privilege-escalation-enabling pattern.
    """
    name = (role_dict.get('name') or '').lower()
    if name in _STRONG_BUILT_IN_ROLE_NAMES:
        return True
    if role_dict.get('custom_subscription_owner_role'):
        return True
    for permission in role_dict.get('permissions') or []:
        for action in permission.actions if hasattr(permission, 'actions') else permission.get('actions', []):
            action_lower = (action or '').lower()
            if action_lower in _STRONG_ACTION_PATTERNS:
                return True
    return False


def _principal_directory_role_tier(principal_id, directory_roles):
    """Highest directory-role privilege tier held by a given principal (user or SP) id."""
    best_tier = _DIRECTORY_ROLE_DEFAULT_TIER
    held_roles = []
    for directory_role in directory_roles.values():
        for member in directory_role.get('members', []):
            if member.get('id') == principal_id:
                held_roles.append(directory_role.get('name'))
                best_tier = max(best_tier, get_directory_role_tier(directory_role.get('name')))
    return best_tier, held_roles


def compute_app_owner_privilege_escalation(applications, service_principals, directory_roles):
    """
    For each non-enterprise Application (App Registration), compares the highest Microsoft
    Graph Application-permission risk tier granted to its corresponding Service Principal
    against the highest Entra directory-role privilege tier held by any of its owners.
    Mutates each application dict in place with:
      - 'granted_permissions_risk_tier' (int) and 'granted_permissions' (list of names)
      - 'max_owner_directory_role_tier' (int) and 'owners_directory_roles' (per-owner detail)
      - 'owner_weaker_than_app_permissions' (bool)
    """
    try:
        service_principal_by_app_id = {
            sp.get('app_id'): sp for sp in service_principals.values() if sp.get('app_id')
        }

        for application in applications.values():
            matching_sp = service_principal_by_app_id.get(application.get('app_id'))

            granted_tier = 0
            granted_permission_names = []
            if matching_sp:
                for assignment in matching_sp.get('granted_app_role_assignments', []):
                    if assignment.get('resource_display_name') != 'Microsoft Graph':
                        continue
                    info = get_graph_permission_info(assignment.get('app_role_id'))
                    if info:
                        granted_permission_names.append(info['name'])
                        granted_tier = max(granted_tier, info['tier'])

            application['granted_permissions_risk_tier'] = granted_tier
            application['granted_permissions'] = sorted(set(granted_permission_names))

            max_owner_tier = _DIRECTORY_ROLE_DEFAULT_TIER
            owners_directory_roles = []
            for owner in application.get('owners', []):
                owner_tier, owner_roles = _principal_directory_role_tier(owner.get('id'), directory_roles)
                owners_directory_roles.append({
                    'id': owner.get('id'),
                    'display_name': owner.get('display_name') or owner.get('user_principal_name'),
                    'directory_roles': owner_roles,
                    'directory_role_tier': owner_tier,
                })
                max_owner_tier = max(max_owner_tier, owner_tier)

            application['max_owner_directory_role_tier'] = max_owner_tier
            application['owners_directory_roles'] = owners_directory_roles

            # Only meaningful when the app actually has owners and was granted at least one
            # tiered permission; an app with no owners can't be escalated-through via an owner.
            application['owner_weaker_than_app_permissions'] = bool(
                application.get('owners') and granted_tier > 0 and max_owner_tier < granted_tier
            )
    except Exception as e:
        print_exception(f'Unable to compute app owner privilege escalation: {e}')


def compute_enterprise_app_subscription_privilege_table(service_principals, rbac_subscriptions):
    """
    Builds (and returns) a table, keyed by a synthetic row id (matching the dict-of-dicts
    convention used throughout ScoutSuite so it can be browsed/ruled-on like any other
    resource), of Enterprise Applications (Service Principals) that hold a 'strong' Azure
    RBAC role directly at subscription scope. Also mutates each such service principal dict
    with 'strong_subscription_roles' (list) + 'has_strong_subscription_role' (bool).
    Each row: service_principal_id, name, app_id, subscription_id, role_name,
    owners (creator approximation).
    """
    table = {}
    try:
        for subscription_id, subscription in rbac_subscriptions.items():
            roles_by_id = subscription.get('roles', {})
            for assignment in subscription.get('role_assignments', {}).values():
                if assignment.get('principal_type') != 'ServicePrincipal':
                    continue
                # Only assignments scoped to the subscription itself (not a narrower RG/resource)
                if assignment.get('scope') != f'/subscriptions/{subscription_id}':
                    continue

                role_id = assignment['role_definition_id'].split('/')[-1]
                role = roles_by_id.get(role_id)
                if not role or not is_subscription_role_strong(role):
                    continue

                service_principal = service_principals.get(assignment['principal_id'])
                if not service_principal:
                    continue

                service_principal.setdefault('strong_subscription_roles', []).append({
                    'subscription_id': subscription_id,
                    'role_name': role.get('name'),
                })

                row_id = f"{service_principal.get('id')}::{subscription_id}::{role_id}"
                table[row_id] = {
                    'id': row_id,
                    'service_principal_id': service_principal.get('id'),
                    'name': service_principal.get('app_name') or service_principal.get('name'),
                    'app_id': service_principal.get('app_id'),
                    'subscription_id': subscription_id,
                    'role_name': role.get('name'),
                    'owners': [
                        owner.get('display_name') or owner.get('user_principal_name') or owner.get('id')
                        for owner in service_principal.get('owners', [])
                    ],
                }

        for service_principal in service_principals.values():
            service_principal['has_strong_subscription_role'] = bool(
                service_principal.get('strong_subscription_roles')
            )
    except Exception as e:
        print_exception(f'Unable to compute enterprise app subscription privilege table: {e}')

    return table
