"""Sub-Store operation metadata shared by the API provisioning scripts."""
from copy import deepcopy
from uuid import uuid4


def ensure_operation_ids(process):
    """Preserve valid IDs and arguments; give every operation a distinct UI key."""
    result = deepcopy(process)
    seen = set()
    for operation in result:
        identifier = operation.get('id')
        if identifier is None or str(identifier) == '' or str(identifier) in seen:
            identifier = uuid4().hex
            operation['id'] = identifier
        seen.add(str(identifier))
    return result
