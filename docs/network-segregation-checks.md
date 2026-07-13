# Azure network segregation checks

This fork adds two Azure network findings covering cross-subscription connectivity and
environment (dev/test/prod) mixing, in addition to the [Entra ID privilege-escalation
checks](entra-privesc-checks.md).

## Terminology note: "VLAN" in Azure

Azure has no ARM-level "VLAN" concept - that's an on-prem/L2 idea. The direct equivalent for
"can these two networks reach each other" in Azure is **VNet Peering**. These checks are built on
VNet Peering; see [Limitations](#limitations) below for what else creates cross-subscription
connectivity that is *not* covered.

## The two findings

1. **`network-cross-subscription-vnet-peering`** (warning) - baseline visibility. Flags every
   active (`peering_state == 'Connected'`) VNet Peering that crosses a subscription boundary at
   all. Cross-subscription peering is common and often intentional (hub-and-spoke connectivity
   subscriptions), so this is reported at low severity to give visibility over the tenant's
   network topology - review each entry and confirm it's documented/intentional.
2. **`network-cross-environment-vnet-peering`** (danger) - the actual segregation violation.
   Flags a peering where the two subscriptions were classified into **different**, known
   environments (e.g. one `production`, the other `development`). This is what "no
   mixing/connectivity between dev/test/production" concretely means at the network layer.

Both findings read the same underlying table, `services.network.cross_subscription_vnet_peerings`
(browsable directly under Networking in the report), built by
`ScoutSuite/providers/azure/network_segregation.py`, wired into
`AzureProvider.preprocessing()`.

## How environment classification works

Azure has no built-in environment taxonomy. Each subscription is classified as `production`,
`staging`, `test`, `development`, or `unknown` from:
1. An `environment`/`env`/`stage` **tag** on the subscription, if present (checked first - more
   explicit signal), or
2. The subscription's **display name**,

matched as case-insensitive substrings against curated pattern lists in
`ScoutSuite/providers/azure/data/network_segregation/environment_classification_patterns.json`
(e.g. `prod`/`prd`/`production` -> `production`; `dev`/`development` -> `development`). This
matches the common enterprise convention of one subscription per environment.

**A subscription that matches no pattern is `unknown` and is never treated as mismatching another
subscription** (known or unknown) - classification under-reports rather than guesses. Tune the
JSON file for your naming convention if it doesn't match the defaults.

## What counts as "connected"

Only peerings with `peering_state == 'Connected'` are considered. An `Initiated` peering is a
one-sided pending request from only one side - no traffic can flow until the other side accepts
it, so it isn't yet a real connection. Same-subscription peerings (two VNets peered within one
subscription) are excluded entirely - that's not a cross-subscription segregation concern.

## Limitations

- **Only native VNet Peering is checked.** VPN Gateway / ExpressRoute connections and Virtual WAN
  hub connectivity across subscriptions are **not** covered - a deliberate v1 scope decision. A
  gateway-based connection between a prod and a dev subscription would not be caught by these
  findings today.
- **Topology, not enforcement.** A peering represents an administrative/topological connection;
  this does not evaluate whether NSGs or route tables actually block traffic on top of it. The
  existence of the peering between different environments is itself the concern being flagged
  (matching how "environments should not share a network" is normally understood), not a
  guarantee that traffic is actually flowing unrestricted.
- **Classification is a heuristic**, as above - it can under-classify (mark something `unknown`)
  but will not fabricate a mismatch.
- Peerings are fetched inline on each Virtual Network resource (Azure has no separate
  list-all-peerings API); a peering pointing at a subscription this scan doesn't have access to
  is still detected as cross-subscription, but the remote subscription's environment is
  necessarily `unknown` (its display name/tags cannot be read), so it will never trigger the
  cross-environment finding on its own.

## Required permissions

No new permissions beyond what ScoutSuite's Azure `network` and `rbac`-equivalent Reader access
already requires - VNets (including their inline peerings) and subscription display names/tags
are read via the same ARM Reader role this fork already needs for the rest of the Network
dashboard.
