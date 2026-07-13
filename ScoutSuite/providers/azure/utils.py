import re


def get_resource_group_name(id):
    return re.findall("/resourceGroups/(.*?)/", id)[0]


def get_subscription_id(id):
    """Extracts the subscription ID from a full Azure ARM resource ID, e.g.
    '/subscriptions/{id}/resourceGroups/...'. Returns None if not found (malformed/short ID)."""
    match = re.findall("/subscriptions/([^/]+)", id or '')
    return match[0] if match else None


def get_resource_name(id):
    """Extracts the last segment (resource name) from a full Azure ARM resource ID."""
    return (id or '').rstrip('/').split('/')[-1] or None
