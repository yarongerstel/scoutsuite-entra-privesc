"""
Cross-resource correlation for the Entra ID (Azure AD) privilege-escalation checks that
cannot be expressed as a single-resource JMESPath rule. Each function below writes derived
fields/flags back onto the relevant resource dicts (following the same pattern as
AzureProvider._match_rbac_roles_and_principals) so that simple declarative JSON findings can
flag them.

Checks implemented here:
 1. App Registration owner weaker than the app's granted permissions
    (compute_app_owner_privilege_escalation)
 2. Enterprise Application (Service Principal) strong subscription-role table, incl. Managed
    Identities (compute_enterprise_app_subscription_privilege_table)
 3. Service Principal owner weaker than the SP's granted permissions
    (compute_sp_owner_privilege_escalation)
 4. Dangerous Microsoft Graph permission combinations held by one app/SP
    (compute_dangerous_permission_combinations)
 5. Overly-broad federated identity credentials (Workload Identity Federation)
    (compute_broad_federated_credentials)
 6. Guest users holding strong directory or subscription roles
    (compute_guest_strong_roles)
 7. Users who hold a strong subscription role while being weak in the directory
    (compute_users_strong_subscription_but_weak_directory)

IMPORTANT / LIMITATIONS (see docs/entra-privesc-checks.md for the full write-up):
 - The permission and directory-role risk tiers are a curated, opinionated heuristic, not an
   authoritative Microsoft ranking. They catch common/well-documented escalation-enabling
   permissions and roles, not an exhaustive classification.
 - Directory roles are matched by their English displayName as returned by Microsoft Graph;
   tenants reporting role names in another display language fall back to the lowest tier.
 - Microsoft Graph API permissions are matched by GUID (appRoleId) against a curated table.
   A permission not in the table is treated as tier 0 / unknown (NOT flagged) rather than
   guessed - this can under-report, it will never over-report.
 - "Who created" an Enterprise Application is approximated via its owners, because Microsoft
   Graph does not expose a `createdBy` field on applications/servicePrincipals.
 - Federated-credential breadth is a heuristic keyed on known CI issuers; a specific subject
   on an unknown issuer is not flagged (conservative under-report).
"""

import json
import os

from ScoutSuite.core.console import print_exception

_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'entra_privesc')

MICROSOFT_GRAPH_APP_ID = '00000003-0000-0000-c000-000000000000'

# A guest holding a directory role at or above this tier (2 = write-capable/admin roles such
# as User Administrator, Groups Administrator, Directory Writers) is considered to hold a
# 'strong' role worth flagging. Tuneable; documented as heuristic.
STRONG_GUEST_DIRECTORY_ROLE_TIER = 2

# A user whose highest directory role is at or below this tier (1 = read-only roles such as
# Directory Readers / Global Reader, 0 = no directory role) is considered a 'weak' identity in
# the directory. Used to flag users who are weak in the directory yet hold a strong Azure RBAC
# role on a subscription. Tuneable; documented as heuristic.
WEAK_USER_DIRECTORY_ROLE_TIER = 1


def _load_json(filename):
    path = os.path.join(_DATA_DIR, filename)
    with open(path, 'r') as f:
        return json.load(f)


_directory_role_tiers_data = _load_json('directory_role_privilege_tiers.json')
_graph_permission_tiers_data = _load_json('graph_application_permission_risk_tiers.json')
_subscription_role_strength_data = _load_json('subscription_role_strength.json')
_dangerous_combinations_data = _load_json('dangerous_permission_combinations.json')
_federated_credential_patterns_data = _load_json('broad_federated_credential_patterns.json')

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
_ROLE_GRANTING_BUILT_IN_ROLE_NAMES = {
    name.lower() for name in _subscription_role_strength_data.get('role_granting_built_in_role_names', [])
}
_ROLE_GRANTING_ACTION_PATTERNS = [
    pattern.lower() for pattern in _subscription_role_strength_data.get('role_granting_action_patterns', [])
]

# List of {name, permissions (set of lowercased names), rationale}
_DANGEROUS_COMBINATIONS = [
    {
        'name': combo['name'],
        'permissions': {p.lower() for p in combo['permissions']},
        'rationale': combo.get('rationale', ''),
    }
    for combo in _dangerous_combinations_data['dangerous_combinations']
]

_FIC_WILDCARD_INDICATORS = _federated_credential_patterns_data['wildcard_subject_indicators']
_FIC_FLEXIBLE_IS_BROAD = _federated_credential_patterns_data.get('flexible_matching_is_broad', True)
_FIC_KNOWN_CI_ISSUERS = _federated_credential_patterns_data['known_ci_issuers']


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
    A subscription-scope RBAC role is 'strong' if it's a well-known high-privilege built-in
    (Owner/Contributor/User Access Administrator), ScoutSuite already flagged it as a wildcard
    custom role (`custom_subscription_owner_role`), or any of its actions match a known
    broad/privilege-escalation-enabling pattern.
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


def is_role_granting_subscription_role(role_dict):
    """
    A subscription-scope RBAC role that can assign OTHER roles - i.e. the privilege-escalation
    primitive itself (Owner, User Access Administrator, RBAC Administrator, or any custom role
    with Microsoft.Authorization/roleAssignments/write or a wildcard). Deliberately narrower than
    is_subscription_role_strong(): Contributor is 'strong' but is NOT role-granting (it cannot
    assign roles), so it is excluded here.
    """
    name = (role_dict.get('name') or '').lower()
    if name in _ROLE_GRANTING_BUILT_IN_ROLE_NAMES:
        return True
    if role_dict.get('custom_subscription_owner_role'):
        return True
    for permission in role_dict.get('permissions') or []:
        for action in permission.actions if hasattr(permission, 'actions') else permission.get('actions', []):
            if (action or '').lower() in _ROLE_GRANTING_ACTION_PATTERNS:
                return True
    return False


def _granted_graph_permissions(granted_app_role_assignments):
    """
    Returns (max_tier, sorted list of tiered permission names) for the Microsoft Graph
    Application permissions actually granted to a service principal.
    """
    max_tier = 0
    names = []
    for assignment in granted_app_role_assignments or []:
        if assignment.get('resource_display_name') != 'Microsoft Graph':
            continue
        info = get_graph_permission_info(assignment.get('app_role_id'))
        if info:
            names.append(info['name'])
            max_tier = max(max_tier, info['tier'])
    return max_tier, sorted(set(names))


def build_eligible_directory_roles_by_principal(role_eligibility_schedules):
    """
    Builds {principal_id: set(role display names)} from the PIM directory-role eligibility
    schedule instances, so a principal who is *eligible* for a privileged role (e.g. can activate
    Global Administrator on demand) is counted as holding that role's privilege - not treated as
    weak just because the role is not currently active under /directoryRoles.
    """
    result = {}
    for instance in (role_eligibility_schedules or {}).values():
        principal_id = instance.get('principal_id')
        role_name = instance.get('role_name')
        if principal_id and role_name:
            result.setdefault(principal_id, set()).add(role_name)
    return result


def _principal_directory_role_tier(principal_id, directory_roles, eligible_roles_by_principal=None):
    """
    Highest directory-role privilege tier held by a given principal (user or SP) id, counting
    both currently-active assignments (/directoryRoles members) and PIM-eligible assignments.
    """
    best_tier = _DIRECTORY_ROLE_DEFAULT_TIER
    held_roles = []
    for directory_role in directory_roles.values():
        for member in directory_role.get('members', []):
            if member.get('id') == principal_id:
                held_roles.append(directory_role.get('name'))
                best_tier = max(best_tier, get_directory_role_tier(directory_role.get('name')))
    for role_name in sorted((eligible_roles_by_principal or {}).get(principal_id, ())):
        held_roles.append(f'{role_name} (PIM eligible)')
        best_tier = max(best_tier, get_directory_role_tier(role_name))
    return best_tier, held_roles


def _max_owner_directory_role(owners, directory_roles, eligible_roles_by_principal=None):
    """Returns (max_tier, per-owner detail list) across an object's owners."""
    max_tier = _DIRECTORY_ROLE_DEFAULT_TIER
    owners_detail = []
    for owner in owners or []:
        owner_tier, owner_roles = _principal_directory_role_tier(
            owner.get('id'), directory_roles, eligible_roles_by_principal)
        owners_detail.append({
            'id': owner.get('id'),
            'display_name': owner.get('display_name') or owner.get('user_principal_name'),
            'directory_roles': owner_roles,
            'directory_role_tier': owner_tier,
        })
        max_tier = max(max_tier, owner_tier)
    return max_tier, owners_detail


def compute_app_owner_privilege_escalation(applications, service_principals, directory_roles,
                                           eligible_roles_by_principal=None):
    """
    For each App Registration, compares the highest Microsoft Graph Application-permission risk
    tier granted to its corresponding Service Principal against the highest Entra directory-role
    privilege tier held by any of its owners (active or PIM-eligible). Mutates each application
    dict with granted_permissions[_risk_tier], max_owner_directory_role_tier,
    owners_directory_roles and owner_weaker_than_app_permissions (bool).
    """
    try:
        service_principal_by_app_id = {
            sp.get('app_id'): sp for sp in service_principals.values() if sp.get('app_id')
        }
        for application in applications.values():
            matching_sp = service_principal_by_app_id.get(application.get('app_id'))
            granted_tier, granted_names = _granted_graph_permissions(
                matching_sp.get('granted_app_role_assignments') if matching_sp else [])

            application['granted_permissions_risk_tier'] = granted_tier
            application['granted_permissions'] = granted_names

            max_owner_tier, owners_detail = _max_owner_directory_role(
                application.get('owners'), directory_roles, eligible_roles_by_principal)
            application['max_owner_directory_role_tier'] = max_owner_tier
            application['owners_directory_roles'] = owners_detail

            application['owner_weaker_than_app_permissions'] = bool(
                application.get('owners') and granted_tier > 0 and max_owner_tier < granted_tier
            )
    except Exception as e:
        print_exception(f'Unable to compute app owner privilege escalation: {e}')


def compute_sp_owner_privilege_escalation(service_principals, directory_roles,
                                          eligible_roles_by_principal=None):
    """
    Same idea as compute_app_owner_privilege_escalation but for Service Principals that have
    their own owners and their own granted permissions. Mutates each SP dict with
    granted_permissions[_risk_tier], max_owner_directory_role_tier, owners_directory_roles and
    owner_weaker_than_app_permissions (bool).
    """
    try:
        for sp in service_principals.values():
            granted_tier, granted_names = _granted_graph_permissions(
                sp.get('granted_app_role_assignments'))
            sp['granted_permissions_risk_tier'] = granted_tier
            sp['granted_permissions'] = granted_names

            max_owner_tier, owners_detail = _max_owner_directory_role(
                sp.get('owners'), directory_roles, eligible_roles_by_principal)
            sp['max_owner_directory_role_tier'] = max_owner_tier
            sp['owners_directory_roles'] = owners_detail

            sp['owner_weaker_than_app_permissions'] = bool(
                sp.get('owners') and granted_tier > 0 and max_owner_tier < granted_tier
            )
    except Exception as e:
        print_exception(f'Unable to compute service principal owner privilege escalation: {e}')


def _matched_dangerous_combinations(granted_permission_names):
    granted_lower = {n.lower() for n in granted_permission_names or []}
    matched = []
    for combo in _DANGEROUS_COMBINATIONS:
        if combo['permissions'].issubset(granted_lower):
            matched.append({'name': combo['name'], 'rationale': combo['rationale']})
    return matched


def compute_dangerous_permission_combinations(applications, service_principals):
    """
    Flags any App Registration or Service Principal whose granted Microsoft Graph permissions
    contain a full dangerous combination (see dangerous_permission_combinations.json). Relies on
    granted_permissions already computed by the owner-privesc functions, so must run after them.
    Mutates each dict with dangerous_permission_combinations (list) and
    has_dangerous_permission_combination (bool).
    """
    try:
        for collection in (applications, service_principals):
            for obj in collection.values():
                matched = _matched_dangerous_combinations(obj.get('granted_permissions'))
                obj['dangerous_permission_combinations'] = matched
                obj['has_dangerous_permission_combination'] = bool(matched)
    except Exception as e:
        print_exception(f'Unable to compute dangerous permission combinations: {e}')


def is_federated_credential_broad(fic):
    """
    Heuristic: a federated identity credential is 'broad' if its subject uses a wildcard, it
    uses flexible claims matching, or (for a known CI issuer) it either contains an
    always-broad substring or is not pinned to a specific branch/tag/environment.
    """
    subject = fic.get('subject') or ''
    for indicator in _FIC_WILDCARD_INDICATORS:
        if indicator in subject:
            return True
    if _FIC_FLEXIBLE_IS_BROAD and fic.get('claims_matching_expression'):
        return True
    issuer = fic.get('issuer') or ''
    for issuer_key, cfg in _FIC_KNOWN_CI_ISSUERS.items():
        if issuer_key in issuer:
            for broad_sub in cfg.get('always_broad_substrings', []):
                if broad_sub in subject:
                    return True
            safe_pins = cfg.get('safe_pin_substrings', [])
            if safe_pins and not any(pin in subject for pin in safe_pins):
                return True
            return False
    return False


def compute_broad_federated_credentials(applications):
    """
    Flags any App Registration that has an overly-broad federated identity credential. Mutates
    each application dict with broad_federated_credentials (list) and
    has_broad_federated_credential (bool).
    """
    try:
        for application in applications.values():
            broad = [
                {'name': fic.get('name'), 'issuer': fic.get('issuer'), 'subject': fic.get('subject')}
                for fic in application.get('federated_identity_credentials', [])
                if is_federated_credential_broad(fic)
            ]
            application['broad_federated_credentials'] = broad
            application['has_broad_federated_credential'] = bool(broad)
    except Exception as e:
        print_exception(f'Unable to compute broad federated credentials: {e}')


def _user_strong_subscription_roles(user, rbac_subscriptions):
    """List of {subscription_id, role_name} of strong subscription RBAC roles held by a user."""
    strong_sub_roles = []
    for assignment in user.get('roles') or []:
        subscription_id = assignment.get('subscription_id')
        role_id = assignment.get('role_id')
        subscription = rbac_subscriptions.get(subscription_id, {}) if rbac_subscriptions else {}
        role = subscription.get('roles', {}).get(role_id)
        if role and is_subscription_role_strong(role):
            strong_sub_roles.append({
                'subscription_id': subscription_id,
                'role_name': role.get('name'),
            })
    return strong_sub_roles


def compute_guest_strong_roles(users, directory_roles, rbac_subscriptions,
                               eligible_roles_by_principal=None):
    """
    Flags any guest user (userType == 'Guest') that holds a strong Entra directory role (tier
    >= STRONG_GUEST_DIRECTORY_ROLE_TIER, active or PIM-eligible) or a strong Azure RBAC role at
    subscription scope. Mutates each guest user dict with held_directory_roles,
    held_strong_subscription_roles and guest_holds_strong_role (bool).
    """
    try:
        for user in users.values():
            if user.get('user_type') != 'Guest':
                continue

            dir_tier, held_roles = _principal_directory_role_tier(
                user.get('id'), directory_roles, eligible_roles_by_principal)
            user['held_directory_roles'] = held_roles

            strong_sub_roles = _user_strong_subscription_roles(user, rbac_subscriptions)
            user['held_strong_subscription_roles'] = strong_sub_roles

            user['guest_holds_strong_role'] = bool(
                dir_tier >= STRONG_GUEST_DIRECTORY_ROLE_TIER or strong_sub_roles
            )
    except Exception as e:
        print_exception(f'Unable to compute guest strong roles: {e}')


def compute_users_strong_subscription_but_weak_directory(users, directory_roles, rbac_subscriptions,
                                                         eligible_roles_by_principal=None):
    """
    Flags any user who holds a strong Azure RBAC role at subscription scope while being a weak
    identity in the directory itself - i.e. their highest Entra directory role is at or below
    WEAK_USER_DIRECTORY_ROLE_TIER (no admin role). PIM-eligible directory roles count too, so a
    user who is merely eligible to activate Global Administrator is NOT treated as weak. Such
    users are powerful on the Azure control plane despite being low-privileged in the directory,
    which concentrates blast radius on ordinary accounts. Mutates each user dict with
    held_strong_subscription_roles, directory_role_tier and
    strong_subscription_role_but_weak_directory (bool).
    """
    try:
        for user in users.values():
            strong_sub_roles = _user_strong_subscription_roles(user, rbac_subscriptions)
            # Preserve any value already set by the guest check (identical computation).
            user['held_strong_subscription_roles'] = strong_sub_roles

            dir_tier, held_roles = _principal_directory_role_tier(
                user.get('id'), directory_roles, eligible_roles_by_principal)
            user.setdefault('held_directory_roles', held_roles)
            user['directory_role_tier'] = dir_tier

            user['strong_subscription_role_but_weak_directory'] = bool(
                strong_sub_roles and dir_tier <= WEAK_USER_DIRECTORY_ROLE_TIER
            )
    except Exception as e:
        print_exception(f'Unable to compute users with strong subscription but weak directory role: {e}')


def compute_enterprise_app_subscription_privilege_table(service_principals, rbac_subscriptions):
    """
    Builds (and returns) a table, keyed by a synthetic row id (matching the dict-of-dicts
    convention used throughout ScoutSuite so it can be browsed/ruled-on like any other
    resource), of Enterprise Applications (Service Principals) that hold a 'strong' Azure RBAC
    role directly at subscription scope. Also mutates each such service principal dict with
    strong_subscription_roles (list) + has_strong_subscription_role (bool). Managed Identities
    are included and distinguished via the service_principal_type column, since a Managed
    Identity with a strong subscription role is a distinct control-plane escalation vector.
    Each row: service_principal_id, name, app_id, service_principal_type, subscription_id,
    role_name, owners (creator approximation).
    """
    table = {}
    try:
        for subscription_id, subscription in rbac_subscriptions.items():
            roles_by_id = subscription.get('roles', {})
            for assignment in subscription.get('role_assignments', {}).values():
                # Match by principal ID against the fetched service principals rather than
                # trusting Azure's reported `principal_type`. Azure Resource Manager's role
                # assignments API can return principalType 'Unknown' for a genuine Service
                # Principal (a known ARM quirk - e.g. when ARM's own AAD lookup at read time
                # doesn't resolve), which would silently hide a real SP-held role if filtered on
                # that field - this mirrors the same robust ID-based approach already used by
                # AzureProvider._match_rbac_roles_and_principals(), which does not check
                # principal_type at all.
                service_principal = service_principals.get(assignment.get('principal_id'))
                if not service_principal:
                    continue

                # Only assignments scoped to the subscription itself (not a narrower RG/resource)
                if assignment.get('scope') != f'/subscriptions/{subscription_id}':
                    continue

                role_id = assignment['role_definition_id'].split('/')[-1]
                role = roles_by_id.get(role_id)
                if not role or not is_subscription_role_strong(role):
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
                    'service_principal_type': service_principal.get('service_principal_type'),
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


def compute_standing_privileged_subscription_assignments(rbac_subscriptions, users=None, groups=None,
                                                         service_principals=None):
    """
    Builds (and returns) a table, keyed by role-assignment id, of every STANDING (active, i.e.
    not PIM just-in-time) role assignment at subscription scope where the role can assign other
    roles (Owner, User Access Administrator, RBAC Administrator, or a custom role with
    roleAssignments/write / wildcard). This is a baseline least-privilege finding - independent
    of the escalation-correlation checks - covering ANY principal type (User, Group, Service
    Principal, Managed Identity), matching the 'persistent privileged access' class of finding.

    Principal type/name are resolved against the fetched aad collections (users/groups/service
    principals) rather than trusting Azure's reported principal_type, which can be 'Unknown'.
    Each row: principal_id, principal_name, principal_type, subscription_id, role_name.
    """
    table = {}
    try:
        def resolve_principal(principal_id):
            for collection, principal_type in (
                    (users, 'User'), (groups, 'Group'), (service_principals, 'ServicePrincipal')):
                obj = collection.get(principal_id) if collection else None
                if obj:
                    name = obj.get('name') or obj.get('display_name') or obj.get('app_name') \
                        or principal_id
                    return name, principal_type
            return principal_id, None

        for subscription_id, subscription in (rbac_subscriptions or {}).items():
            roles_by_id = subscription.get('roles', {})
            for assignment in subscription.get('role_assignments', {}).values():
                if assignment.get('scope') != f'/subscriptions/{subscription_id}':
                    continue
                role_id = assignment['role_definition_id'].split('/')[-1]
                role = roles_by_id.get(role_id)
                if not role or not is_role_granting_subscription_role(role):
                    continue

                principal_id = assignment.get('principal_id')
                principal_name, resolved_type = resolve_principal(principal_id)
                row_id = assignment.get('id') or f"{principal_id}::{subscription_id}::{role_id}"
                table[row_id] = {
                    'id': row_id,
                    'principal_id': principal_id,
                    'principal_name': principal_name,
                    # Prefer the type resolved from the fetched directory objects; fall back to
                    # Azure's reported type (which may be 'Unknown').
                    'principal_type': resolved_type or assignment.get('principal_type'),
                    'subscription_id': subscription_id,
                    'role_name': role.get('name'),
                }
    except Exception as e:
        print_exception(f'Unable to compute standing privileged subscription assignments: {e}')

    return table


def _principals_with_strong_subscription_role(rbac_subscriptions):
    """
    Returns {subscription_id: set(principal_ids)} of principals that already hold a strong role
    directly at that subscription's scope. Used to tell whether an app owner already has the
    subscription access their app would grant them.
    """
    result = {}
    for subscription_id, subscription in (rbac_subscriptions or {}).items():
        roles_by_id = subscription.get('roles', {})
        strong_principals = set()
        for assignment in subscription.get('role_assignments', {}).values():
            if assignment.get('scope') != f'/subscriptions/{subscription_id}':
                continue
            role_id = assignment['role_definition_id'].split('/')[-1]
            role = roles_by_id.get(role_id)
            if role and is_subscription_role_strong(role):
                strong_principals.add(assignment.get('principal_id'))
        result[subscription_id] = strong_principals
    return result


def compute_app_owner_subscription_escalation(applications, service_principals, rbac_subscriptions,
                                              groups=None):
    """
    Flags an App Registration whose service principal holds a strong Azure RBAC role at
    subscription scope when an owner of the app does NOT already hold a strong role on that same
    subscription. Such an owner can add credentials to the application, authenticate as its
    service principal, and thereby gain subscription-level control (Owner/Contributor/etc.) that
    they do not otherwise have - escalating from (often directory-only) app ownership to control
    of an Azure subscription. This is the subscription/Azure-RBAC counterpart to the
    directory/Graph-permission owner check (compute_app_owner_privilege_escalation).

    An owner is considered to already have subscription access if they hold a strong role
    directly OR through membership in a group that holds a strong role on that subscription.

    Must run AFTER compute_enterprise_app_subscription_privilege_table, which populates each
    service principal's strong_subscription_roles. Mutates each application dict with
    owner_subscription_escalations (list of {owner, subscription_id, role_name}) and
    owner_escalates_to_subscription (bool).

    Limitation: group membership resolution is best-effort, based on the group memberships
    ScoutSuite has fetched (guests + users referenced by role assignments); an owner whose group
    membership was not fetched cannot be resolved and may still be flagged.
    """
    try:
        sp_by_app_id = {
            sp.get('app_id'): sp for sp in service_principals.values() if sp.get('app_id')
        }
        strong_principals_by_sub = _principals_with_strong_subscription_role(rbac_subscriptions)
        # group_id -> set(member ids). Populated by AAD.assign_group_memberships().
        group_members = {
            group_id: set(group.get('users') or [])
            for group_id, group in (groups or {}).items()
        }

        def owner_has_subscription_access(owner_id, subscription_id):
            strong_principals = strong_principals_by_sub.get(subscription_id, set())
            if owner_id in strong_principals:
                return True
            # via group membership: a strong principal that is a group containing the owner
            for principal_id in strong_principals:
                if owner_id in group_members.get(principal_id, ()):
                    return True
            return False

        for application in applications.values():
            matching_sp = sp_by_app_id.get(application.get('app_id'))
            app_strong_sub_roles = matching_sp.get('strong_subscription_roles', []) if matching_sp else []

            escalations = []
            for owner in application.get('owners', []):
                owner_id = owner.get('id')
                owner_label = owner.get('display_name') or owner.get('user_principal_name') or owner_id
                for role in app_strong_sub_roles:
                    subscription_id = role.get('subscription_id')
                    if not owner_has_subscription_access(owner_id, subscription_id):
                        escalations.append({
                            'owner': owner_label,
                            'subscription_id': subscription_id,
                            'role_name': role.get('role_name'),
                        })

            application['owner_subscription_escalations'] = escalations
            application['owner_escalates_to_subscription'] = bool(escalations)
    except Exception as e:
        print_exception(f'Unable to compute app owner subscription escalation: {e}')
