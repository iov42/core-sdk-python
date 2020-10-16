"""Test cases for request entity."""
import json
import uuid

from iov42.core._entity import AssetType
from iov42.core._entity import Entity
from iov42.core._entity import Identity
from iov42.core._entity import Operation
from iov42.core._entity import Request
from iov42.core._entity import Response


def test_request_with_id() -> None:
    """Request with value."""
    request = Request(Operation.WRITE, Entity(), id="123456")
    assert request.id == "123456"
    assert str(request) == "123456"


def test_generated_request() -> None:
    """Generated request is a UUID."""
    request = Request(Operation.READ, Entity())
    assert uuid.UUID(str(request))


def test_request_repr() -> None:
    """Printable representation of a request."""
    # TODO: what information do we want to show in here?
    entity = Request(Operation.READ, Entity(), id="123456")
    assert repr(entity) == "Request(id=123456)"


def test_create_identiy_request_content(identity: Identity) -> None:
    """Content of a request to create an identiy."""
    request = Request(Operation.WRITE, entity=identity)
    content = json.loads(request.content)
    assert content["_type"] == "IssueIdentityRequest"
    assert uuid.UUID(content["requestId"])
    assert content["identityId"] == identity.identity_id
    assert (
        content["publicCredentials"]["protocolId"] == identity.private_key.protocol.name
    )
    assert (
        content["publicCredentials"]["key"] == identity.private_key.public_key().dump()
    )
    # TODO: the test does not check if the body contains only the desired keys.


def test_create_asset_request_content(identity: Identity) -> None:
    """Content of a request to create an identiy."""
    asset_type = AssetType("085f2066-d469-4a45-b7d8-b12f145a2e59")
    request = Request(Operation.WRITE, asset_type)

    content = json.loads(request.content)
    assert content["_type"] == "DefineAssetTypeRequest"
    assert content["type"] == "Unique"
    assert content["assetTypeId"] == "085f2066-d469-4a45-b7d8-b12f145a2e59"
    assert uuid.UUID(content["requestId"])
    # TODO: the test does not check if the body contains only the desired keys.


def test_response() -> None:
    """Request with value."""
    response = Response(
        "123456",
        proof="/api/v1/proofs/e9c79db4-2b8b-439f-95f5-7574005458ef",
        resources=["/api/v1/identities/itest-id-0a9ad8d5-cb84-4f3d-ae7b-94687fe4d7a0"],
    )
    assert response.request_id == "123456"
    assert str(response) == "Response(request_id=123456)"


def test_response_repr() -> None:
    """Printable representation of a request."""
    response = Response(
        "123456",
        proof="/api/v1/proofs/e9c79db4-2b8b-439f-95f5-7574005458ef",
        resources=["/api/v1/identities/itest-id-0a9ad8d5-cb84-4f3d-ae7b-94687fe4d7a0"],
    )
    assert repr(response) == (
        "Response(request_id=123456,proof='/api/v1/proofs/e9c79db4-2b8b-439f-95f5-7574005458ef',"
        "resources=['/api/v1/identities/itest-id-0a9ad8d5-cb84-4f3d-ae7b-94687fe4d7a0'])"
    )
