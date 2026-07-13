from ScoutSuite.providers.azure.resources.base import AzureResources


class RoleEligibilitySchedules(AzureResources):
    """
    PIM 'eligible' directory role assignments: principals who can activate a directory role
    (e.g. Global Administrator) on demand via Privileged Identity Management. Fetched separately
    from /directoryRoles, which only lists currently-active assignments - so that a principal who
    is eligible for a privileged role is not mistaken for one holding no directory role at all.
    """

    async def fetch_all(self):
        for raw_instance in await self.facade.aad.get_directory_role_eligibility_schedule_instances():
            id, instance = self._parse_instance(raw_instance)
            if id:
                self[id] = instance

    def _parse_instance(self, raw_instance):
        role_definition = raw_instance.get('roleDefinition') or {}
        instance = {
            'id': raw_instance.get('id'),
            'principal_id': raw_instance.get('principalId'),
            'role_definition_id': raw_instance.get('roleDefinitionId'),
            'role_name': role_definition.get('displayName'),
            'role_template_id': role_definition.get('templateId'),
        }
        return instance['id'], instance
