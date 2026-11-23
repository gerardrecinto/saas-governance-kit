import pytest
from fastapi.testclient import TestClient

from saas_governance_kit.scim.app import create_app
from saas_governance_kit.scim.store import ScimStore

TOKEN = "test-token-123"
H = {"Authorization": f"Bearer {TOKEN}"}
U = "urn:ietf:params:scim:schemas:core:2.0:User"
G = "urn:ietf:params:scim:schemas:core:2.0:Group"
P = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
B = "/scim/v2"


@pytest.fixture
def client():
    return TestClient(create_app(ScimStore(), TOKEN))


def mk_user(client, name="alice@example.com", **extra):
    body = {"schemas": [U], "userName": name, "emails": [{"value": name, "type": "work"}], **extra}
    r = client.post(f"{B}/Users", json=body, headers=H)
    assert r.status_code == 201, r.text
    return r.json()


def test_auth_required_and_constant_time(client):
    assert client.get(f"{B}/Users").status_code == 401
    assert client.get(f"{B}/Users", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get(f"{B}/Users", headers={"Authorization": f"Basic {TOKEN}"}).status_code == 401
    assert client.get(f"{B}/Users", headers=H).status_code == 200


def test_empty_token_rejected():
    with pytest.raises(ValueError):
        create_app(ScimStore(), "")


def test_user_crud(client):
    u = mk_user(client)
    assert u["active"] is True and u["meta"]["resourceType"] == "User"
    got = client.get(f"{B}/Users/{u['id']}", headers=H).json()
    assert got["userName"] == "alice@example.com"
    put = client.put(
        f"{B}/Users/{u['id']}",
        json={"schemas": [U], "userName": "alice@example.com", "displayName": "Alice"},
        headers=H,
    )
    assert put.json()["displayName"] == "Alice"
    assert client.delete(f"{B}/Users/{u['id']}", headers=H).status_code == 204
    assert client.get(f"{B}/Users/{u['id']}", headers=H).status_code == 404


def test_duplicate_username_409(client):
    mk_user(client)
    r = client.post(f"{B}/Users", json={"schemas": [U], "userName": "ALICE@example.com"}, headers=H)
    assert r.status_code == 409
    assert r.json()["scimType"] == "uniqueness"


def test_validation_errors(client):
    r = client.post(f"{B}/Users", json={"schemas": [U]}, headers=H)
    assert r.status_code == 400
    r = client.post(f"{B}/Users", content="not json", headers=H)
    assert r.status_code == 400


def test_okta_style_deactivate_patch(client):
    u = mk_user(client)
    payload = {"schemas": [P], "Operations": [{"op": "replace", "value": {"active": False}}]}
    r = client.patch(f"{B}/Users/{u['id']}", json=payload, headers=H)
    assert r.status_code == 200
    assert r.json()["active"] is False


def test_azure_style_capitalized_op_and_path(client):
    u = mk_user(client)
    payload = {
        "schemas": [P],
        "Operations": [
            {"op": "Replace", "path": "active", "value": False},
            {"op": "Add", "path": "name.givenName", "value": "Alice"},
            {"op": "replace", "path": 'emails[type eq "work"].value', "value": "a@new.example.com"},
        ],
    }
    r = client.patch(f"{B}/Users/{u['id']}", json=payload, headers=H).json()
    assert r["active"] is False
    assert r["name"]["givenName"] == "Alice"
    assert r["emails"][0]["value"] == "a@new.example.com"


def test_patch_remove_attribute_and_bad_ops(client):
    u = mk_user(client, displayName="Al")
    ok = client.patch(
        f"{B}/Users/{u['id']}",
        json={"schemas": [P], "Operations": [{"op": "remove", "path": "displayName"}]},
        headers=H,
    ).json()
    assert "displayName" not in ok
    bad = client.patch(
        f"{B}/Users/{u['id']}",
        json={"schemas": [P], "Operations": [{"op": "move", "path": "x"}]},
        headers=H,
    )
    assert bad.status_code == 400
    assert (
        client.patch(f"{B}/Users/{u['id']}", json={"Operations": []}, headers=H).status_code == 400
    )


def test_patch_cannot_change_id(client):
    u = mk_user(client)
    r = client.patch(
        f"{B}/Users/{u['id']}",
        json={"schemas": [P], "Operations": [{"op": "replace", "value": {"id": "evil"}}]},
        headers=H,
    ).json()
    assert r["id"] == u["id"]


def test_group_membership_patch(client):
    u1, u2 = mk_user(client, "a@x.com"), mk_user(client, "b@x.com")
    g = client.post(
        f"{B}/Groups", json={"schemas": [G], "displayName": "eng", "members": []}, headers=H
    ).json()
    add = {
        "schemas": [P],
        "Operations": [
            {"op": "add", "path": "members", "value": [{"value": u1["id"]}, {"value": u2["id"]}]}
        ],
    }
    r = client.patch(f"{B}/Groups/{g['id']}", json=add, headers=H).json()
    assert {m["value"] for m in r["members"]} == {u1["id"], u2["id"]}
    # adding the same member again does not duplicate
    r = client.patch(f"{B}/Groups/{g['id']}", json=add, headers=H).json()
    assert len(r["members"]) == 2
    rem = {
        "schemas": [P],
        "Operations": [{"op": "remove", "path": f'members[value eq "{u1["id"]}"]'}],
    }
    r = client.patch(f"{B}/Groups/{g['id']}", json=rem, headers=H).json()
    assert [m["value"] for m in r["members"]] == [u2["id"]]
    rep = {"schemas": [P], "Operations": [{"op": "replace", "path": "members", "value": []}]}
    assert client.patch(f"{B}/Groups/{g['id']}", json=rep, headers=H).json()["members"] == []


def test_group_unknown_member_rejected_and_user_delete_cleans_groups(client):
    u = mk_user(client)
    r = client.post(
        f"{B}/Groups",
        json={"schemas": [G], "displayName": "bad", "members": [{"value": "nope"}]},
        headers=H,
    )
    assert r.status_code == 400
    g = client.post(
        f"{B}/Groups",
        json={"schemas": [G], "displayName": "ok", "members": [{"value": u["id"]}]},
        headers=H,
    ).json()
    client.delete(f"{B}/Users/{u['id']}", headers=H)
    assert client.get(f"{B}/Groups/{g['id']}", headers=H).json()["members"] == []


def test_filters_and_pagination(client):
    for i in range(5):
        mk_user(client, f"user{i}@corp.com")
    mk_user(client, "bob@other.org")
    q = lambda **p: client.get(f"{B}/Users", params=p, headers=H).json()  # noqa: E731
    assert q(filter='userName eq "bob@other.org"')["totalResults"] == 1
    assert q(filter='userName co "corp"')["totalResults"] == 5
    assert q(filter='userName co "user" and emails.value co "other"')["totalResults"] == 0
    assert q(filter='userName co "user" and active eq true')["totalResults"] == 5
    page = q(startIndex=2, count=2)
    assert page["totalResults"] == 6 and page["itemsPerPage"] == 2 and page["startIndex"] == 2
    assert q(count=0)["Resources"] == []
    bad = client.get(f"{B}/Users", params={"filter": "garbage"}, headers=H)
    assert bad.status_code == 400 and bad.json()["scimType"] == "invalidFilter"


def test_filter_value_containing_and(client):
    mk_user(client, "rock and roll@x.com")
    r = client.get(f"{B}/Users", params={"filter": 'userName eq "rock and roll@x.com"'}, headers=H)
    assert r.json()["totalResults"] == 1


def test_discovery_endpoints(client):
    assert client.get(f"{B}/ServiceProviderConfig", headers=H).json()["patch"]["supported"] is True
    assert client.get(f"{B}/Schemas", headers=H).json()["totalResults"] == 2
    ids = [r["id"] for r in client.get(f"{B}/ResourceTypes", headers=H).json()["Resources"]]
    assert ids == ["User", "Group"]


def test_json_file_store_persists(tmp_path):
    path = tmp_path / "scim.json"
    c1 = TestClient(create_app(ScimStore(path), TOKEN))
    u = mk_user(c1)
    c2 = TestClient(create_app(ScimStore(path), TOKEN))
    assert c2.get(f"{B}/Users/{u['id']}", headers=H).status_code == 200
