"""Tests to create entities on the iov42 platform."""
import json
import uuid
from typing import Type
from typing import Union

import pytest
import respx

from iov42.core import Asset
from iov42.core import AssetType
from iov42.core import Client
from iov42.core import CryptoProtocol
from iov42.core import Identity


@pytest.mark.parametrize("entity", [(Identity), (AssetType()), (Asset(AssetType()))])
def test_call_to_endpoint(
    client: Client,
    mocked_requests_200: respx.MockTransport,
    entity: Union[Type[Identity], AssetType, Asset],
) -> None:
    """Corret endpoint is called once."""
    request_id = str(uuid.uuid4())
    _ = client.put(entity, request_id=request_id)
    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    assert str(http_request.url).rsplit("/", 1)[1] == request_id


@pytest.mark.parametrize("entity", [(Identity), (AssetType()), (Asset(AssetType()))])
def test_header_content_type(
    client: Client,
    mocked_requests_200: respx.MockTransport,
    entity: Union[Type[Identity], AssetType, Asset],
) -> None:
    """Header content-type is JSON."""
    _ = client.put(entity)
    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    assert http_request.headers["content-type"] == "application/json"


@pytest.mark.parametrize("entity", [(Identity), (AssetType()), (Asset(AssetType()))])
def test_generated_request_id(
    client: Client,
    mocked_requests_200: respx.MockTransport,
    entity: Union[Type[Identity], AssetType, Asset],
) -> None:
    """Request ID is a generated UUID."""
    _ = client.put(entity)
    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    # We have to call read(), otherwise we get an httpx.RequestNoRead reading
    # the content (see https://github.com/lundberg/respx/issues/83).
    content = json.loads(http_request.read())
    assert uuid.UUID(content["requestId"])


def test_create_identity_content(
    client: Client,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """Request content to create the identity provided with the client."""
    request_id = str(uuid.uuid4())
    _ = client.put(Identity, request_id=request_id)

    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    content = json.loads(http_request.read())
    assert content == {
        "_type": "IssueIdentityRequest",
        "requestId": request_id,
        "identityId": client.identity.id,
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
    # TODO: should we raise exception if a different instance than the one in
    # the client is provided?
    _ = client.put(identity, request_id=request_id)

    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    content = json.loads(http_request.read())
    assert content == {
        "_type": "IssueIdentityRequest",
        "requestId": request_id,
        "identityId": identity.id,
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
        "assetTypeId": entity.id,
        "type": entity.type,
        "requestId": request_id,
    }


def test_create_uniqe_asset_content(
    client: Client,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """Request content to create an asset-type."""
    request_id = str(uuid.uuid4())
    entity = Asset(AssetType())

    _ = client.put(entity, request_id=request_id)

    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    content = json.loads(http_request.read())
    assert content == {
        "_type": "CreateAssetRequest",
        "assetId": entity.id,
        "assetTypeId": entity.asset_type.id,
        "requestId": request_id,
    }


@pytest.mark.parametrize("entity", [(Identity), (AssetType()), (Asset(AssetType()))])
def test_response(
    client: Client,
    mocked_requests_200: respx.MockTransport,
    entity: Union[Identity, AssetType],
) -> None:
    """Content of the platform response to the create identity request."""
    request_id = str(uuid.uuid4())
    response = client.put(entity, request_id=request_id)
    assert response.request_id == request_id
    assert response.proof == "/api/v1/proofs/" + request_id


def test_response_identity(
    client: Client,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """Platform response to the create an identity."""
    response = client.put(Identity)
    assert response.resources == ["/api/v1/identities/" + client.identity.id]


def test_response_asset_type(
    client: Client,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """Platform response to the create an asset type."""
    entity = AssetType()
    response = client.put(entity)
    assert response.resources == ["/api/v1/asset-types/" + entity.id]


def test_response_asset(
    client: Client,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """Platform response to the create an asset type."""
    entity = Asset(AssetType())
    response = client.put(entity)
    assert response.resources == [
        "/".join(("/api/v1/asset-types", entity.asset_type.id, "assets", entity.id))
    ]
