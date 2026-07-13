from ScoutSuite.providers.azure.resources.base import AzureResources
from ScoutSuite.providers.azure.resources.aad.owners import normalize_owners
from ScoutSuite.providers.utils import map_concurrently


class ServicePrincipals(AzureResources):
    async def fetch_all(self):
        raw_service_principals = await self.facade.aad.get_service_principals()
        # Exclude built-in Microsoft service principals BEFORE issuing the per-SP Graph calls
        # (owners, appRoleAssignments, oauth2 grants) - otherwise those calls are made and then
        # thrown away for every first-party Microsoft SP (there are often hundreds).
        raw_service_principals = [
            raw for raw in raw_service_principals
            if raw.get('publisherName') != 'Microsoft Services'
        ]
        # Parse the remaining service principals concurrently.
        parsing_results = await map_concurrently(
            self._parse_service_principal, raw_service_principals)
        for id, service_principal in parsing_results:
            self[id] = service_principal

    async def _parse_service_principal(self, raw_service_principal):
        service_principal_dict = {}
        service_principal_dict['id'] = raw_service_principal.get('id')
        service_principal_dict['name'] = raw_service_principal.get('displayName')
        # service_principal_dict['additional_properties'] = raw_service_principal.additional_properties
        service_principal_dict['deletion_timestamp'] = raw_service_principal.get('deletedDateTime')
        service_principal_dict['object_type'] = 'ServicePrincipal'
        service_principal_dict['account_enabled'] = raw_service_principal.get('accountEnabled')
        service_principal_dict['alternative_names'] = raw_service_principal.get('alternativeNames')
        service_principal_dict['app_name'] = raw_service_principal.get('appDisplayName')
        service_principal_dict['app_id'] = raw_service_principal.get('appId')
        service_principal_dict['app_owner_tenant_id'] = raw_service_principal.get('appOwnerOrganizationId')
        service_principal_dict['app_role_assignment_required'] = raw_service_principal.get('appRoleAssignmentRequired')
        service_principal_dict['app_roles'] = raw_service_principal.get('appRoles')
        service_principal_dict['error_url'] = raw_service_principal.get('errorUrl')
        service_principal_dict['homepage'] = raw_service_principal.get('homepage')
        service_principal_dict['key_credentials'] = raw_service_principal.get('keyCredentials')
        service_principal_dict['logout_url'] = raw_service_principal.get('logoutUrl')
        service_principal_dict['oauth2_permissions'] = raw_service_principal.get('oauth2PermissionScopes')
        service_principal_dict['password_credentials'] = raw_service_principal.get('passwordCredentials')
        service_principal_dict[
            'preferred_token_signing_key_thumbprint'] = raw_service_principal.get('preferredTokenSigningKeyThumbprint')
        service_principal_dict['publisher_name'] = raw_service_principal.get('publisherName')
        service_principal_dict['reply_urls'] = raw_service_principal.get('replyUrls')
        service_principal_dict['saml_metadata_url'] = raw_service_principal.get('samlMetadataUrl')
        service_principal_dict['service_principal_names'] = raw_service_principal.get('servicePrincipalNames')
        service_principal_dict['service_principal_type'] = raw_service_principal.get('servicePrincipalType')
        service_principal_dict['tags'] = raw_service_principal.get('tags')

        service_principal_dict['roles'] = []  # this will be filled in `finalize()`

        raw_owners = await self.facade.aad.get_service_principal_owners(service_principal_dict['id'])
        service_principal_dict['owners'] = normalize_owners(raw_owners)

        # Application (API) permissions actually granted to this app, e.g. Microsoft Graph
        # app roles such as Directory.ReadWrite.All - the "permissions the app received".
        raw_app_role_assignments = await self.facade.aad.get_service_principal_app_role_assignments(
            service_principal_dict['id'])
        service_principal_dict['granted_app_role_assignments'] = [
            {
                'id': assignment.get('id'),
                'app_role_id': assignment.get('appRoleId'),
                'resource_id': assignment.get('resourceId'),
                'resource_display_name': assignment.get('resourceDisplayName'),
            }
            for assignment in raw_app_role_assignments or []
        ]

        raw_oauth2_permission_grants = await self.facade.aad.get_service_principal_oauth2_permission_grants(
            service_principal_dict['id'])
        service_principal_dict['granted_oauth2_permission_grants'] = [
            {
                'id': grant.get('id'),
                'resource_id': grant.get('resourceId'),
                'consent_type': grant.get('consentType'),
                'scope': grant.get('scope'),
            }
            for grant in raw_oauth2_permission_grants or []
        ]

        return service_principal_dict['id'], service_principal_dict

