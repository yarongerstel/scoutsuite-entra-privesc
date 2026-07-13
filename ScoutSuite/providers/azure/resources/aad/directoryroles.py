from ScoutSuite.providers.azure.resources.base import AzureResources
from ScoutSuite.providers.azure.resources.aad.owners import normalize_owners
from ScoutSuite.providers.utils import map_concurrently


class DirectoryRoles(AzureResources):
    """
    Entra ID directory roles (Global Administrator, Privileged Role Administrator, etc.)
    that are currently activated in the tenant, along with their members. Only activated
    roles are returned by Microsoft Graph's /directoryRoles endpoint - a role with nobody
    ever assigned to it does not show up here.
    """

    async def fetch_all(self):
        # Each _parse_directory_role fetches the role's members, so fan them out concurrently.
        parsing_results = await map_concurrently(
            self._parse_directory_role, await self.facade.aad.get_directory_roles())
        for id, directory_role in parsing_results:
            self[id] = directory_role

    async def _parse_directory_role(self, raw_directory_role):
        directory_role_dict = {}
        directory_role_dict['id'] = raw_directory_role.get('id')
        directory_role_dict['name'] = raw_directory_role.get('displayName')
        directory_role_dict['role_template_id'] = raw_directory_role.get('roleTemplateId')
        directory_role_dict['description'] = raw_directory_role.get('description')

        raw_members = await self.facade.aad.get_directory_role_members(directory_role_dict['id'])
        directory_role_dict['members'] = normalize_owners(raw_members)

        return directory_role_dict['id'], directory_role_dict
