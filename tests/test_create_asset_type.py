"""Tests to create an asset type."""
import base64
import json
import uuid

import pytest
import respx

from iov42.core import AssetType
from iov42.core import Client
from iov42.core import InvalidSignature


def test_create_asset_type_call_endpoint(
    client: Client,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """It sends a HTTP request to create an asset-type."""
    _ = client.create_asset_type(AssetType())

    assert mocked_requests_200["create_entity"].call_count == 1


def test_create_asset_type_content_type(
    client: Client,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """It sends a request header with the expected content-type."""
    _ = client.create_asset_type(AssetType())

    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    assert http_request.headers["content-type"] == "application/json"


def test_create_asset_type_no_id(
    client: Client,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """It generates an UUID for the asset type ID if it is not."""
    _ = client.create_asset_type(AssetType())

    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    content = json.loads(http_request.read())
    assert uuid.UUID(content["assetTypeId"])


def test_create_asset_type_default_request_id(
    client: Client,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """It generates an UUID for the request ID if the request ID is not provided."""
    _ = client.create_asset_type(AssetType())

    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    content = json.loads(http_request.read())
    assert uuid.UUID(content["requestId"])


def test_create_asset_type_content(
    client: Client,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """It sends the request body to create an asset type as expected."""
    _ = client.create_asset_type(
        AssetType("085f2066-d469-4a45-b7d8-b12f145a2e59"),
        request_id="f4031c4a-5c1c-4cd2-9776-2826481bc855",
    )

    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    content = json.loads(http_request.read())
    assert content["_type"] == "DefineAssetTypeRequest"
    assert content["type"] == "Unique"
    assert content["assetTypeId"] == "085f2066-d469-4a45-b7d8-b12f145a2e59"
    assert content["requestId"] == "f4031c4a-5c1c-4cd2-9776-2826481bc855"


def str_decode(data: str) -> str:
    """Standard decoding of strings."""
    return base64.urlsafe_b64decode(data + "==").decode()


def test_create_asset_type_authorisations_header(
    client: Client,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """Content of x-iov42-authorisations header to create an asset type."""
    _ = client.create_asset_type(
        AssetType("085f2066-d469-4a45-b7d8-b12f145a2e59"),
        request_id="f4031c4a-5c1c-4cd2-9776-2826481bc855",
    )

    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    # TODO: we need an authorisation verifcation anyway. Clean up the code when
    # we have it.
    authorisations = json.loads(
        str_decode(http_request.headers["x-iov42-authorisations"])
    )

    assert len(authorisations) == 1
    assert authorisations[0]["identityId"] == client.identity.identity_id
    assert authorisations[0]["protocolId"] == client.identity.private_key.protocol.name


def test_create_asset_type_authorisations_signatursignature(
    client: Client,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """Content of x-iov42-authorisations header to create an asset type."""
    _ = client.create_asset_type(
        AssetType("085f2066-d469-4a45-b7d8-b12f145a2e59"),
        request_id="f4031c4a-5c1c-4cd2-9776-2826481bc855",
    )

    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    authorisations = json.loads(
        str_decode(http_request.headers["x-iov42-authorisations"])
    )
    try:
        content = http_request.read().decode()
        client.identity.verify_signature(authorisations[0]["signature"], content)
    except InvalidSignature:
        pytest.fail("Signature verification failed")


def test_create_asset_type_authentication_header(
    client: Client,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """Content of x-iov42-authentication header to create an asset type."""
    _ = client.create_asset_type(
        AssetType("085f2066-d469-4a45-b7d8-b12f145a2e59"),
        request_id="f4031c4a-5c1c-4cd2-9776-2826481bc855",
    )

    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    authentication = json.loads(
        str_decode(http_request.headers["x-iov42-authentication"])
    )

    assert (
        authentication["identityId"] == "itest-id-0a9ad8d5-cb84-4f3d-ae7b-94687fe4d7a0"
    )


def test_create_asset_type_authentication_header_signature(
    client: Client,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """Verifies signature of x-iov42-authentication header."""
    _ = client.create_asset_type(
        AssetType("085f2066-d469-4a45-b7d8-b12f145a2e59"),
        request_id="f4031c4a-5c1c-4cd2-9776-2826481bc855",
    )

    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    authorisations_signatures = ";".join(
        [
            s["signature"]
            for s in json.loads(
                str_decode(http_request.headers["x-iov42-authorisations"])
            )
        ]
    )
    authentication = json.loads(
        str_decode(http_request.headers["x-iov42-authentication"])
    )

    try:
        client.identity.verify_signature(
            authentication["signature"], authorisations_signatures
        )
    except InvalidSignature:
        pytest.fail("Signature verification failed")


def test_create_asset_type_response(
    client: Client,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """Content of the platform response to the create identity request."""
    response = client.create_asset_type(
        AssetType("085f2066-d469-4a45-b7d8-b12f145a2e59"),
        request_id="f4031c4a-5c1c-4cd2-9776-2826481bc855",
    )

    assert response.request_id == "f4031c4a-5c1c-4cd2-9776-2826481bc855"
    assert response.proof == "/api/v1/proofs/f4031c4a-5c1c-4cd2-9776-2826481bc855"
    assert response.resources == [
        "/api/v1/asset-types/085f2066-d469-4a45-b7d8-b12f145a2e59"
    ]


# From here on we have the error handling


@respx.mock
@pytest.mark.parametrize(
    "invalid_asset_type_id",
    [("asset-type-€"), ("asset type"), ("asset%type"), ("asset/type")],
)
def test_invalid_asset_type_id(client: Client, invalid_asset_type_id: str) -> None:
    """Raise exception if the provided request ID contains invalid charatcers."""
    with pytest.raises(ValueError) as excinfo:
        client.create_asset_type(AssetType(invalid_asset_type_id))
    # No request was sent
    assert not respx.calls

    assert (
        str(excinfo.value)
        == f"invalid identifier '{invalid_asset_type_id}' - valid characters are [a-zA-Z0-9._\\-+]"
    )


@respx.mock
@pytest.mark.parametrize(
    "invalid_request_id",
    [("request-€"), ("%-request"), ("request-/")],
)
def test_invalid_request_id(client: Client, invalid_request_id: str) -> None:
    """Raise exception if the provided request ID contains invalid charatcers."""
    with pytest.raises(ValueError) as excinfo:
        client.create_asset_type(AssetType(), request_id=invalid_request_id)
    # No request was sent
    assert not respx.calls

    assert (
        str(excinfo.value)
        == f"invalid identifier '{invalid_request_id}' - valid characters are [a-zA-Z0-9._\\-+]"
    )
