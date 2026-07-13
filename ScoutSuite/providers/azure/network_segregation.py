"""
Cross-subscription network segregation checks for Azure VNets.

Azure has no ARM-level "VLAN" concept (that's an on-prem/L2 idea); the direct equivalent for
"should two networks be reachable from each other" is VNet Peering. This module flags:

 1. Any VNet Peering that crosses a subscription boundary at all (baseline visibility - common
    and often legitimate in hub-spoke architectures, so reported at low/warning severity).
 2. A VNet Peering that connects two subscriptions classified into DIFFERENT, non-"unknown"
    environments (e.g. one 'production', the other 'development') - the actual segregation
    violation the user asked about ("no mixing/connectivity between dev/test/prod"), reported at
    danger severity.

LIMITATIONS (see docs/network-segregation-checks.md for the full write-up):
 - Only native VNet Peering is checked. VPN Gateway / ExpressRoute connections and Virtual WAN
   hub connectivity across subscriptions are NOT covered - a deliberate v1 scope decision, not an
   oversight; a gateway-based connection between environments would not be caught here.
 - Environment classification is a curated heuristic based on subscription display name (and an
   'environment'-style tag if present) - see environment_classification_patterns.json. A
   subscription that doesn't match any pattern is 'unknown' and is never treated as mismatching
   another subscription (whether known or unknown) - this can under-report, it will never guess.
 - A peering only represents an administrative/topological connection; this does not evaluate
   whether NSGs/route tables actually block traffic on top of it. The peering itself is the
   segregation concern being flagged (matching how "no shared network between environments" is
   normally understood - as a topology statement, not a firewall-rule audit).
 - Only 'Connected' peerings are considered (an 'Initiated' peering is a one-sided pending
   request that does not yet allow any traffic).
"""

import json
import os

from ScoutSuite.core.console import print_exception
from ScoutSuite.providers.azure.utils import get_subscription_id

_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'network_segregation')


def _load_json(filename):
    with open(os.path.join(_DATA_DIR, filename), 'r') as f:
        return json.load(f)


_classification_data = _load_json('environment_classification_patterns.json')
_TAG_KEYS_CHECKED = [k.lower() for k in _classification_data.get('tag_keys_checked', [])]
# Ordered so a name matching multiple classes (unlikely, but possible) resolves consistently.
_ENVIRONMENT_ORDER = ['production', 'staging', 'test', 'development']
_ENVIRONMENT_PATTERNS = {
    env: [p.lower() for p in _classification_data['environment_patterns'].get(env, [])]
    for env in _ENVIRONMENT_ORDER
}


def classify_subscription_environment(display_name, tags=None):
    """
    Classifies a subscription's environment from its display name and/or an environment-style tag
    (see tag_keys_checked), matched as case-insensitive substrings. Returns one of 'production',
    'staging', 'test', 'development', or 'unknown' if nothing matches. Tag values are checked
    first (more explicit/intentional signal than a name), then the display name.
    """
    candidates = []
    for key, value in (tags or {}).items():
        if key.lower() in _TAG_KEYS_CHECKED and value:
            candidates.append(str(value).lower())
    if display_name:
        candidates.append(display_name.lower())

    for candidate in candidates:
        for env in _ENVIRONMENT_ORDER:
            if any(pattern in candidate for pattern in _ENVIRONMENT_PATTERNS[env]):
                return env
    return 'unknown'


def compute_cross_subscription_vnet_peerings(network_subscriptions):
    """
    Builds (and returns) a table, keyed by a synthetic row id, of every 'Connected' VNet peering
    that crosses a subscription boundary. Each row records both subscriptions' classified
    environment and whether the pair is a cross-environment mismatch. Also mutates each VNet dict
    with has_cross_subscription_peering / has_cross_environment_peering (bool).

    :param network_subscriptions: self.services['network']['subscriptions'] - dict of
        subscription_id -> {'display_name', 'tags', 'virtual_networks': {...}, ...}
    """
    table = {}
    try:
        subscription_environments = {
            sub_id: classify_subscription_environment(sub.get('display_name'), sub.get('tags'))
            for sub_id, sub in network_subscriptions.items()
        }
        subscription_names = {
            sub_id: sub.get('display_name') or sub_id for sub_id, sub in network_subscriptions.items()
        }

        for local_subscription_id, subscription in network_subscriptions.items():
            local_environment = subscription_environments.get(local_subscription_id, 'unknown')
            local_subscription_name = subscription_names.get(local_subscription_id, local_subscription_id)

            for vnet_id, vnet in subscription.get('virtual_networks', {}).items():
                has_cross_subscription_peering = False
                has_cross_environment_peering = False

                for peering in vnet.get('virtual_network_peerings', []):
                    if peering.get('peering_state') != 'Connected':
                        continue
                    remote_subscription_id = peering.get('remote_subscription_id')
                    if not remote_subscription_id or remote_subscription_id == local_subscription_id:
                        continue

                    remote_environment = subscription_environments.get(remote_subscription_id, 'unknown')
                    remote_subscription_name = subscription_names.get(
                        remote_subscription_id,
                        f'{remote_subscription_id} (not in scanned scope)')

                    is_cross_environment = (
                        local_environment != 'unknown' and remote_environment != 'unknown'
                        and local_environment != remote_environment
                    )

                    has_cross_subscription_peering = True
                    has_cross_environment_peering = has_cross_environment_peering or is_cross_environment

                    row_id = f"{local_subscription_id}::{vnet_id}::{peering.get('id')}"
                    table[row_id] = {
                        'id': row_id,
                        'name': f"{vnet.get('name')} ({local_subscription_name}) <-> "
                                f"{peering.get('remote_virtual_network_name')} ({remote_subscription_name})",
                        'local_subscription_id': local_subscription_id,
                        'local_subscription_name': local_subscription_name,
                        'local_environment': local_environment,
                        'local_virtual_network_name': vnet.get('name'),
                        'remote_subscription_id': remote_subscription_id,
                        'remote_subscription_name': remote_subscription_name,
                        'remote_environment': remote_environment,
                        'remote_virtual_network_name': peering.get('remote_virtual_network_name'),
                        'peering_name': peering.get('name'),
                        'allow_virtual_network_access': peering.get('allow_virtual_network_access'),
                        'is_cross_environment': is_cross_environment,
                    }

                vnet['has_cross_subscription_peering'] = has_cross_subscription_peering
                vnet['has_cross_environment_peering'] = has_cross_environment_peering
    except Exception as e:
        print_exception(f'Unable to compute cross-subscription VNet peerings: {e}')

    return table
