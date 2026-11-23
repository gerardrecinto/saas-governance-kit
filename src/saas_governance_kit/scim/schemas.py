USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
SPC_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"

SERVICE_PROVIDER_CONFIG = {
    "schemas": [SPC_SCHEMA],
    "patch": {"supported": True},
    "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
    "filter": {"supported": True, "maxResults": 200},
    "changePassword": {"supported": False},
    "sort": {"supported": False},
    "etag": {"supported": False},
    "authenticationSchemes": [
        {
            "type": "oauthbearertoken",
            "name": "OAuth Bearer Token",
            "description": "Authentication scheme using the OAuth Bearer Token Standard",
            "specUri": "https://www.rfc-editor.org/info/rfc6750",
            "primary": True,
        }
    ],
}

RESOURCE_TYPES = [
    {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
        "id": "User",
        "name": "User",
        "endpoint": "/Users",
        "schema": USER_SCHEMA,
    },
    {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
        "id": "Group",
        "name": "Group",
        "endpoint": "/Groups",
        "schema": GROUP_SCHEMA,
    },
]


def _attr(name, type_="string", **kw):
    base = {
        "name": name,
        "type": type_,
        "multiValued": False,
        "required": False,
        "mutability": "readWrite",
        "returned": "default",
        "uniqueness": "none",
    }
    base.update(kw)
    return base


SCHEMAS = [
    {
        "id": USER_SCHEMA,
        "name": "User",
        "description": "User Account",
        "attributes": [
            _attr("userName", required=True, uniqueness="server"),
            _attr("displayName"),
            _attr("active", "boolean"),
            _attr("externalId"),
            _attr("name", "complex"),
            _attr("emails", "complex", multiValued=True),
        ],
    },
    {
        "id": GROUP_SCHEMA,
        "name": "Group",
        "description": "Group",
        "attributes": [
            _attr("displayName", required=True, uniqueness="server"),
            _attr("members", "complex", multiValued=True),
        ],
    },
]
