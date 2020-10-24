"""Tests to create entities on the iov42 platform."""
import json
import uuid

import pytest
import respx

from iov42.core import Asset
from iov42.core import AssetType
from iov42.core import Client
from iov42.core import CryptoProtocol
from iov42.core import Entity
from iov42.core import Identity

entities = [
    (Identity(CryptoProtocol.SHA256WithECDSA.generate_private_key())),
    (AssetType()),
    (Asset(asset_type_id="123456")),
]


@pytest.mark.parametrize("entity", entities)
def test_call_to_endpoint(
    client: Client, mocked_requests_200: respx.MockTransport, entity: Entity
) -> None:
    """Corret endpoint is called once."""
    request_id = str(uuid.uuid4())
    _ = client.put(entity, request_id=request_id)
    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    assert str(http_request.url).rsplit("/", 1)[1] == request_id


@pytest.mark.parametrize("entity", entities)
def test_header_content_type(
    client: Client, mocked_requests_200: respx.MockTransport, entity: Entity
) -> None:
    """Header content-type is JSON."""
    _ = client.put(entity)
    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    assert http_request.headers["content-type"] == "application/json"


@pytest.mark.parametrize("entity", entities)
def test_generated_request_id(
    client: Client, mocked_requests_200: respx.MockTransport, entity: Entity
) -> None:
    """Request ID is a generated UUID."""
    _ = client.put(entity)
    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    # We have to call read(), otherwise we get an httpx.RequestNoRead reading
    # the content (see https://github.com/lundberg/respx/issues/83).
    content = json.loads(http_request.read())
    assert uuid.UUID(content["requestId"])
    assert str(http_request.url).rsplit("/", 1)[1] == content["requestId"]


def test_create_identity_content(
    client: Client,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """Request content to create the identity provided with the client."""
    request_id = str(uuid.uuid4())
    _ = client.put(client.identity, request_id=request_id)

    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    content = json.loads(http_request.read())
    assert content == {
        "_type": "IssueIdentityRequest",
        "requestId": request_id,
        "identityId": client.identity.identity_id,
        "publicCredentials": {
            "protocolId": client.identity.private_key.protocol.name,
            "key": client.identity.private_key.public_key().dump(),
        },
    }


# TODO: this would still fail since the request is sent with the
# client.identy (having a different key). We takle this when we implement the
# creation of a delegated identity.
# Note: we want to enforce that each identity uses its own client instance.
def test_create_another_identity_content(
    client: Client,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """Request content to create a different identity."""
    request_id = str(uuid.uuid4())
    identity = Identity(CryptoProtocol.SHA256WithRSA.generate_private_key())

    _ = client.put(identity, request_id=request_id)

    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    content = json.loads(http_request.read())
    assert content == {
        "_type": "IssueIdentityRequest",
        "requestId": request_id,
        "identityId": identity.identity_id,
        "publicCredentials": {
            "protocolId": identity.private_key.protocol.name,
            "key": identity.private_key.public_key().dump(),
        },
    }


def test_create_asset_type_content(
    client: Client,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """Request content to create an asset-type."""
    request_id = str(uuid.uuid4())
    entity = AssetType()

    _ = client.put(entity, request_id=request_id)

    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    content = json.loads(http_request.read())
    assert content == {
        "_type": "DefineAssetTypeRequest",
        "assetTypeId": entity.asset_type_id,
        "type": entity.type,
        "requestId": request_id,
    }


def test_create_uniqe_asset_content(
    client: Client,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """Request content to create an asset-type."""
    request_id = str(uuid.uuid4())
    entity = Asset(asset_type_id="123456")

    _ = client.put(entity, request_id=request_id)

    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    content = json.loads(http_request.read())
    assert content == {
        "_type": "CreateAssetRequest",
        "assetId": entity.asset_id,
        "assetTypeId": entity.asset_type_id,
        "requestId": request_id,
    }


@pytest.mark.parametrize("entity", entities)
def test_response(
    client: Client, mocked_requests_200: respx.MockTransport, entity: Entity
) -> None:
    """Content of the platform response to the create identity request."""
    request_id = str(uuid.uuid4())
    response = client.put(entity, request_id=request_id)
    assert response.proof == "/api/v1/proofs/" + request_id
    assert len(response.resources) == 1  # type: ignore[union-attr]


def test_response_identity(
    client: Client,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """Platform response to the create an identity."""
    response = client.put(client.identity)
    assert response.resources == [  # type: ignore[union-attr]
        "/api/v1/identities/" + client.identity.identity_id
    ]


def test_response_asset_type(
    client: Client,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """Platform response to the create an asset type."""
    entity = AssetType()
    response = client.put(entity)
    assert response.resources == ["/api/v1/asset-types/" + entity.asset_type_id]  # type: ignore[union-attr]


def test_response_asset(
    client: Client,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """Platform response to the create an asset type."""
    entity = Asset(asset_type_id=str(uuid.uuid4()))
    response = client.put(entity)
    assert response.resources == [  # type: ignore[union-attr]
        "/".join(
            ("/api/v1/asset-types", entity.asset_type_id, "assets", entity.asset_id)
        )
    ]
