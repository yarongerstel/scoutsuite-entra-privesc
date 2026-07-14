import os

from ScoutSuite.core.console import print_exception

from ScoutSuite.providers.base.provider import BaseProvider
from ScoutSuite.providers.azure.services import AzureServicesConfig
from ScoutSuite.providers.azure import entra_privesc
from ScoutSuite.providers.azure import network_segregation


class AzureProvider(BaseProvider):
    """
    Implements provider for Azure
    """

    def __init__(self,
                 subscription_ids=[], all_subscriptions=None,
                 report_dir=None, timestamp=None, services=None, skipped_services=None,
                 result_format='json',
                 **kwargs):
        services = [] if services is None else services
        skipped_services = [] if skipped_services is None else skipped_services

        self.metadata_path = '%s/metadata.json' % os.path.split(os.path.abspath(__file__))[0]

        self.provider_code = 'azure'
        self.provider_name = 'Microsoft Azure'
        self.environment = 'default'

        self.programmatic_execution = kwargs['programmatic_execution']
        self.credentials = kwargs['credentials']

        if subscription_ids:
            self.subscription_ids = subscription_ids
        elif self.credentials.default_subscription_id:
            self.subscription_ids = [self.credentials.default_subscription_id]
        else:
            self.subscription_ids = []
        self.all_subscriptions = all_subscriptions

        try:
            self.account_id = self.credentials.get_tenant_id()
        except Exception as e:
            self.account_id = 'undefined'

        self.services = AzureServicesConfig(self.credentials,
                                            programmatic_execution=self.programmatic_execution,
                                            subscription_ids=self.subscription_ids,
                                            all_subscriptions=self.all_subscriptions)

        self.result_format = result_format

        super().__init__(report_dir, timestamp,
                                            services, skipped_services, result_format)

    def get_report_name(self):
        """
        Returns the name of the report using the provider's configuration
        """
        try:
            return f'azure-tenant-{self.credentials.get_tenant_id()}'
        except Exception as e:
            print_exception(f'Unable to define report name: {e}')
            return 'azure'

    def preprocessing(self, ip_ranges=None, ip_ranges_name_key=None):
        """
        Tweak the Azure config to match cross-service resources and clean any fetching artifacts

        :param ip_ranges:
        :param ip_ranges_name_key:
        :return: None
        """
        ip_ranges = [] if ip_ranges is None else ip_ranges

        # Don't do this if we're running a local execution
        if not self.last_run:
            self._match_rbac_roles_and_principals()
            self._compute_entra_privesc_checks()
            self._compute_network_segregation_checks()

        super().preprocessing()

    def _compute_network_segregation_checks(self):
        """
        Computes cross-subscription VNet peering / environment-segregation checks (see
        ScoutSuite.providers.azure.network_segregation for details).
        """
        try:
            if 'network' in self.service_list:
                table = network_segregation.compute_cross_subscription_vnet_peerings(
                    network_subscriptions=self.services['network']['subscriptions'])
                self.services['network']['cross_subscription_vnet_peerings'] = table
                self.services['network']['cross_subscription_vnet_peerings_count'] = len(table)
        except Exception as e:
            print_exception(f'Unable to compute network segregation checks: {e}')

    def _compute_entra_privesc_checks(self):
        """
        Computes the Entra ID privilege-escalation cross-resource checks (see
        ScoutSuite.providers.azure.entra_privesc for details): App Registration and Service
        Principal owner-vs-granted-permissions, dangerous permission combinations, overly-broad
        federated identity credentials, guest users with strong roles, and the Enterprise
        Application (incl. Managed Identity) strong subscription-role table.
        """
        try:
            if 'aad' in self.service_list:
                aad = self.services['aad']
                rbac_subscriptions = self.services['rbac']['subscriptions'] \
                    if 'rbac' in self.service_list else {}

                # PIM-eligible directory roles (e.g. principals who can activate Global
                # Administrator) so that eligibility counts toward directory privilege and an
                # eligible admin is not mistaken for a weak identity.
                eligible_roles_by_principal = entra_privesc.build_eligible_directory_roles_by_principal(
                    aad.get('role_eligibility_schedules', {}))

                entra_privesc.compute_app_owner_privilege_escalation(
                    applications=aad['applications'],
                    service_principals=aad['service_principals'],
                    directory_roles=aad['directory_roles'],
                    eligible_roles_by_principal=eligible_roles_by_principal)

                entra_privesc.compute_sp_owner_privilege_escalation(
                    service_principals=aad['service_principals'],
                    directory_roles=aad['directory_roles'],
                    eligible_roles_by_principal=eligible_roles_by_principal)

                # Must run after the owner-privesc functions, which populate granted_permissions
                entra_privesc.compute_dangerous_permission_combinations(
                    applications=aad['applications'],
                    service_principals=aad['service_principals'])

                entra_privesc.compute_broad_federated_credentials(
                    applications=aad['applications'])

                entra_privesc.compute_guest_strong_roles(
                    users=aad['users'],
                    directory_roles=aad['directory_roles'],
                    rbac_subscriptions=rbac_subscriptions,
                    eligible_roles_by_principal=eligible_roles_by_principal)

                entra_privesc.compute_users_strong_subscription_but_weak_directory(
                    users=aad['users'],
                    directory_roles=aad['directory_roles'],
                    rbac_subscriptions=rbac_subscriptions,
                    eligible_roles_by_principal=eligible_roles_by_principal)

            if 'aad' in self.service_list and 'rbac' in self.service_list:
                table = entra_privesc.compute_enterprise_app_subscription_privilege_table(
                    service_principals=self.services['aad']['service_principals'],
                    rbac_subscriptions=self.services['rbac']['subscriptions'])
                self.services['aad']['enterprise_apps_with_strong_subscription_roles'] = table
                # The HTML report only paginates/loads a resource that has a matching *_count key.
                self.services['aad']['enterprise_apps_with_strong_subscription_roles_count'] = len(table)

                # Must run after the table above, which populates strong_subscription_roles.
                entra_privesc.compute_app_owner_subscription_escalation(
                    applications=self.services['aad']['applications'],
                    service_principals=self.services['aad']['service_principals'],
                    rbac_subscriptions=self.services['rbac']['subscriptions'],
                    groups=self.services['aad']['groups'])

                # Baseline: every standing (active) role-granting assignment at subscription scope,
                # for any principal type - independent of the escalation-correlation checks. Grouped
                # per subscription (mirroring Roles/RoleAssignments/CustomRolesReport) rather than
                # one flat cross-subscription table, so a principal holding this on N subscriptions
                # shows as N clearly-labelled per-subscription rows instead of N look-alike flat
                # rows distinguished only by a small subscription_id field.
                entra_privesc.compute_standing_privileged_subscription_assignments(
                    rbac_subscriptions=self.services['rbac']['subscriptions'],
                    users=self.services['aad']['users'],
                    groups=self.services['aad']['groups'],
                    service_principals=self.services['aad']['service_principals'])
                # Not part of RBAC's statically-declared _children, so unlike roles_count etc. this
                # aggregate isn't summed automatically by Subscriptions._set_counts() - do it here.
                self.services['rbac']['standing_privileged_role_assignments_count'] = sum(
                    subscription.get('standing_privileged_role_assignments_count', 0)
                    for subscription in self.services['rbac']['subscriptions'].values())

            if 'rbac' in self.service_list:
                # Only needs rbac (role definitions + assignments), independent of AAD.
                entra_privesc.compute_high_privilege_custom_roles(
                    rbac_subscriptions=self.services['rbac']['subscriptions'])
        except Exception as e:
            print_exception(f'Unable to compute Entra privilege escalation checks: {e}')

    def _match_rbac_roles_and_principals(self):
        """
        Matches ARM role assignments to AAD service principals
        """
        try:
            if 'rbac' in self.service_list and 'aad' in self.service_list:
                for subscription in self.services['rbac']['subscriptions']:
                    for assignment in self.services['rbac']['subscriptions'][subscription]['role_assignments'].values():
                        role_id = assignment['role_definition_id'].split('/')[-1]
                        for group in self.services['aad']['groups']:
                            if group == assignment['principal_id']:
                                self.services['aad']['groups'][group]['roles'].append({'subscription_id': subscription,
                                                                                     'role_id': role_id})
                                self.services['rbac']['subscriptions'][subscription]['roles'][role_id]['assignments']['groups'].append(group)
                                self.services['rbac']['subscriptions'][subscription]['roles'][role_id]['assignments_count'] += 1
                        for user in self.services['aad']['users']:
                            if user == assignment['principal_id']:
                                self.services['aad']['users'][user]['roles'].append({'subscription_id': subscription,
                                                                                     'role_id': role_id})
                                self.services['rbac']['subscriptions'][subscription]['roles'][role_id]['assignments']['users'].append(user)
                                self.services['rbac']['subscriptions'][subscription]['roles'][role_id]['assignments_count'] += 1
                        for service_principal in self.services['aad']['service_principals']:
                            if service_principal == assignment['principal_id']:
                                self.services['aad']['service_principals'][service_principal]['roles'].append({'subscription_id': subscription,
                                                                                                               'role_id': role_id})
                                self.services['rbac']['subscriptions'][subscription]['roles'][role_id]['assignments']['service_principals'].append(service_principal)
                                self.services['rbac']['subscriptions'][subscription]['roles'][role_id]['assignments_count'] += 1
        except Exception as e:
            print_exception('Unable to match RBAC roles and principals: {}'.format(e))
