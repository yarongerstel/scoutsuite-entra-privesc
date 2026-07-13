import asyncio
import os

from msgraph.core import GraphClient

from ScoutSuite.core.console import print_exception
from ScoutSuite.providers.utils import run_concurrently

# Microsoft Graph throttles per-app/per-tenant, and the limits are not published as a fixed
# number - so rather than asking the user to guess a `--max-rate`, the fetch self-throttles:
#   1. A concurrency cap keeps the parallel fan-out to a safe number of in-flight Graph calls.
#   2. HTTP 429 responses are retried honouring the `Retry-After` header Graph returns, so the
#      fetch automatically slows down exactly as much as Graph asks, then speeds back up.
# The cap can be overridden with SCOUT_AZURE_GRAPH_MAX_CONCURRENCY, but the default just works.
GRAPH_MAX_CONCURRENCY = int(os.environ.get('SCOUT_AZURE_GRAPH_MAX_CONCURRENCY', '15'))
GRAPH_MAX_THROTTLE_RETRIES = 5


class AADFacade:

    def __init__(self, credentials):
        self.credentials = credentials
        self._graph_semaphore = None

    def _get_graph_semaphore(self):
        # Created lazily so it binds to the running event loop (there is exactly one per scan).
        if self._graph_semaphore is None:
            self._graph_semaphore = asyncio.Semaphore(GRAPH_MAX_CONCURRENCY)
        return self._graph_semaphore

    async def _graph_get(self, client, endpoint):
        """
        Perform a single Graph GET in the thread-pool executor, bounded by the concurrency
        semaphore and self-throttling on HTTP 429 by honouring the Retry-After header.
        """
        response = None
        for attempt in range(GRAPH_MAX_THROTTLE_RETRIES + 1):
            async with self._get_graph_semaphore():
                response = await run_concurrently(lambda: client.get(endpoint))
            if response.status_code == 429 and attempt < GRAPH_MAX_THROTTLE_RETRIES:
                retry_after = response.headers.get('Retry-After') if hasattr(response, 'headers') else None
                delay = int(retry_after) if retry_after and str(retry_after).isdigit() else 2 ** attempt
                await asyncio.sleep(delay)
                continue
            return response
        return response

    async def _get_microsoft_graph_response(self, api_resource, api_version='v1.0'):
        scopes = ['https://graph.microsoft.com/.default']

        client = GraphClient(credential=self.credentials.get_credentials(), scopes=scopes)
        endpoint = 'https://graph.microsoft.com/{}/{}'.format(api_version, api_resource)
        try:
            # msgraph-core 0.2.2's GraphClient is synchronous (requests-based); _graph_get runs
            # it in the thread-pool executor (so the blocking HTTP call does not freeze the event
            # loop and calls run concurrently) with concurrency-capping and 429 self-throttling.
            response = await self._graph_get(client, endpoint)
            if response.status_code == 200:
                return response.json()
            # If response is 404 then it means there is no resource associated with the provided id
            elif response.status_code == 404:
                return {}
            else:
                print_exception('Failed to query Microsoft Graph endpoint \"{}\": status code {}'.
                                format(api_resource, response.status_code))
                return {}
        except Exception as e:
            print_exception('Failed to query Microsoft Graph endpoint \"{}\": {}'.format(api_resource, e))
            return {}

    async def _get_microsoft_graph_response_paginated(self, api_resource, api_version='v1.0'):
        """
        Same as _get_microsoft_graph_response() but follows @odata.nextLink until exhausted,
        since owners/appRoleAssignments/role members collections can exceed a single page.
        """
        scopes = ['https://graph.microsoft.com/.default']
        client = GraphClient(credential=self.credentials.get_credentials(), scopes=scopes)
        endpoint = 'https://graph.microsoft.com/{}/{}'.format(api_version, api_resource)

        values = []
        try:
            while endpoint:
                response = await self._graph_get(client, endpoint)
                if response.status_code == 200:
                    response_json = response.json()
                    values.extend(response_json.get('value', []))
                    endpoint = response_json.get('@odata.nextLink')
                elif response.status_code == 404:
                    break
                else:
                    print_exception('Failed to query Microsoft Graph endpoint \"{}\": status code {}'.
                                    format(api_resource, response.status_code))
                    break
        except Exception as e:
            print_exception('Failed to query Microsoft Graph endpoint \"{}\": {}'.format(api_resource, e))
        return values

    async def get_users(self):
        try:
            # This filters down the users which are pulled from the directory, otherwise for large tenants this
            # becomes out of hands
            # See https://github.com/nccgroup/ScoutSuite/issues/698
            user_filter = '?$filter=userType+eq+%27Guest%27'
            users_response_beta = await self._get_microsoft_graph_response('users'+ user_filter, 'beta')
            if users_response_beta:
                users = users_response_beta.get('value')
                return users
            return users_response_beta
        except Exception as e:
            print_exception(f'Failed to retrieve users: {e}')
            return []

    async def get_user(self, user_id):
        try:
            user_filter = f'?$filter=id+eq+%27{user_id}%27'
            user_response_beta = await self._get_microsoft_graph_response('users'+user_filter, 'beta')
            if user_response_beta:
                users = user_response_beta.get('value')
                return users[0]
            return user_response_beta
        except Exception as e:
            print_exception(f'Failed to retrieve user {user_id}: {e}')
            return None

    async def get_groups(self):
        try:
            groups_response = await self._get_microsoft_graph_response('groups')
            if groups_response:
                groups = groups_response.get('value')
                return groups
            return groups_response
        except Exception as e:
            print_exception(f'Failed to retrieve groups: {e}')
            return []

    async def get_user_groups(self, group_id):
        try:
            group_filter = f'?$filter=id+eq+%27{group_id}%27'
            user_groups_response = await self._get_microsoft_graph_response('groups' + group_filter)
            if user_groups_response:
                groups = user_groups_response.get('value')
                return groups
            return user_groups_response
        except Exception as e:
            print_exception(f'Failed to retrieve user\'s groups: {e}')
            return []

    async def get_service_principals(self):
        try:
            # Need publisher name value for serviceprincipals.py. v1.0 does not have that value, thus we use beta
            service_principals_response_beta = await self._get_microsoft_graph_response('servicePrincipals', 'beta')
            if service_principals_response_beta:
                service_principals = service_principals_response_beta.get('value')
                return service_principals
            return service_principals_response_beta
        except Exception as e:
            print_exception(f'Failed to retrieve service principals: {e}')
            return []

    async def get_applications(self):
        try:
            applications_response = await self._get_microsoft_graph_response('applications')
            if applications_response:
                applications = applications_response.get('value')
                return applications
            return applications_response
        except Exception as e:
            print_exception(f'Failed to retrieve applications: {e}')
            return []

    async def get_policies(self):
        try:
            policies_response = await self._get_microsoft_graph_response('policies/authorizationPolicy')
            return policies_response
        except Exception as e:
            print_exception(f'Failed to retrieve policies: {e}')
            return []

    async def get_application_owners(self, application_id):
        try:
            return await self._get_microsoft_graph_response_paginated(
                f'applications/{application_id}/owners')
        except Exception as e:
            print_exception(f'Failed to retrieve owners for application {application_id}: {e}')
            return []

    async def get_application_federated_identity_credentials(self, application_id):
        """
        Federated identity credentials (Workload Identity Federation) configured on the
        application - each trusts an external OIDC issuer + subject to authenticate AS the
        app without a client secret/certificate.
        """
        try:
            return await self._get_microsoft_graph_response_paginated(
                f'applications/{application_id}/federatedIdentityCredentials')
        except Exception as e:
            print_exception(
                f'Failed to retrieve federated identity credentials for application {application_id}: {e}')
            return []

    async def get_service_principal_owners(self, service_principal_id):
        try:
            return await self._get_microsoft_graph_response_paginated(
                f'servicePrincipals/{service_principal_id}/owners')
        except Exception as e:
            print_exception(f'Failed to retrieve owners for service principal {service_principal_id}: {e}')
            return []

    async def get_service_principal_app_role_assignments(self, service_principal_id):
        """
        Application (API) permissions that have actually been granted TO this service
        principal (i.e. the permissions the app can use), as opposed to appRoles merely
        defined/exposed BY it. This is the "what permissions did the app receive" data.
        """
        try:
            return await self._get_microsoft_graph_response_paginated(
                f'servicePrincipals/{service_principal_id}/appRoleAssignments')
        except Exception as e:
            print_exception(
                f'Failed to retrieve app role assignments for service principal {service_principal_id}: {e}')
            return []

    async def get_service_principal_oauth2_permission_grants(self, service_principal_id):
        """
        Delegated permission grants (consent) where this service principal is the client.
        """
        try:
            grant_filter = f'?$filter=clientId+eq+%27{service_principal_id}%27'
            return await self._get_microsoft_graph_response_paginated('oauth2PermissionGrants' + grant_filter)
        except Exception as e:
            print_exception(
                f'Failed to retrieve oauth2 permission grants for service principal {service_principal_id}: {e}')
            return []

    async def get_directory_roles(self):
        """
        Only ACTIVATED directory roles are returned by /directoryRoles (Entra AD only
        activates a role template the first time it is assigned to someone).
        """
        try:
            return await self._get_microsoft_graph_response_paginated('directoryRoles')
        except Exception as e:
            print_exception(f'Failed to retrieve directory roles: {e}')
            return []

    async def get_directory_role_eligibility_schedule_instances(self):
        """
        PIM 'eligible' directory role assignments - principals who can activate a directory role
        (e.g. Global Administrator) on demand. These do NOT appear under /directoryRoles members
        (which lists only currently-active assignments), so a PIM-eligible admin would otherwise
        look like they hold no directory role. roleDefinition is expanded to get the role name.
        """
        try:
            return await self._get_microsoft_graph_response_paginated(
                'roleManagement/directory/roleEligibilityScheduleInstances?$expand=roleDefinition')
        except Exception as e:
            print_exception(f'Failed to retrieve directory role eligibility schedule instances: {e}')
            return []

    async def get_directory_role_members(self, directory_role_id):
        try:
            return await self._get_microsoft_graph_response_paginated(
                f'directoryRoles/{directory_role_id}/members')
        except Exception as e:
            print_exception(f'Failed to retrieve members for directory role {directory_role_id}: {e}')
            return []
