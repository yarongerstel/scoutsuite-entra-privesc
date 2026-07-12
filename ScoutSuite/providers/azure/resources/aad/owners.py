def normalize_owners(raw_owners):
    """
    Projects the fields ScoutSuite's privesc checks need out of a raw Graph
    directoryObject list returned by an /owners endpoint (users or, less commonly,
    service principals can own an application/service principal).
    """
    owners = []
    for raw_owner in raw_owners or []:
        owners.append({
            'id': raw_owner.get('id'),
            'object_type': raw_owner.get('@odata.type', '').replace('#microsoft.graph.', ''),
            'display_name': raw_owner.get('displayName'),
            'user_principal_name': raw_owner.get('userPrincipalName'),
        })
    return owners
