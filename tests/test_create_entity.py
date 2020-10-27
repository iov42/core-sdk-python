"""Tests to create entities on the iov42 platform.

The tests perform the actual PUT request. Server responses are mocked.
"""
import json
import typing
import uuid

import pytest
import respx

from iov42.core import Asset
from iov42.core import AssetType
from iov42.core import Client
from iov42.core import CryptoProtocol
from iov42.core import Entity
from iov42.core import Identity
from iov42.core import InvalidSignature
from iov42.core._crypto import iov42_decode
from iov42.core._entity import Claim

entities = [
    (Identity(CryptoProtocol.SHA256WithECDSA.generate_private_key())),
    (AssetType()),
    (Asset(asset_type_id="123456")),
]


@pytest.mark.parametrize("entity", entities)
def test_call_to_put_endpoint(
    client: Client, mocked_requests_200: respx.MockTransport, entity: Entity
) -> None:
    """Corret endpoint is called once."""
    request_id = str(uuid.uuid4())
    _ = client.put(entity, request_id=request_id)
    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    assert str(http_request.url).rsplit("/", 1)[1] == request_id


@pytest.mark.parametrize("entity", entities)
def test_generated_request_id(
    client: Client, mocked_requests_200: respx.MockTransport, entity: Entity
) -> None:
    """If no request ID is provided a UUID is generated."""
    _ = client.put(entity)
    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    # We have to call read(), otherwise we get an httpx.RequestNoRead reading
    # the content (see https://github.com/lundberg/respx/issues/83).
    content = json.loads(http_request.read())
    assert uuid.UUID(content["requestId"])


@pytest.mark.parametrize("entity", entities)
def test_header_content_type(
    client: Client, mocked_requests_200: respx.MockTransport, entity: Entity
) -> None:
    """PUT request content-type is JSON."""
    _ = client.put(entity)
    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    assert http_request.headers["content-type"] == "application/json"


@pytest.mark.parametrize("entity", entities)
def test_iov42_headers(
    client: Client, mocked_requests_200: respx.MockTransport, entity: Entity
) -> None:
    """Authentication and authorisations are created with the request."""
    _ = client.put(entity)

    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    assert "x-iov42-authorisations" in [*http_request.headers]
    assert "x-iov42-authentication" in [*http_request.headers]


# TODO: the created identity is signed with client.identity which would not
# work. Look into this when we have to use case to add an authorisation of a 2nd
# identity.
@pytest.mark.parametrize("entity", entities)
def test_authorisations_header(
    client: Client, mocked_requests_200: respx.MockTransport, entity: Entity
) -> None:
    """Content of x-iov42-authorisations header to create an entity."""
    _ = client.put(entity)

    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    authorisations = json.loads(
        iov42_decode(http_request.headers["x-iov42-authorisations"].encode())
    )
    assert len(authorisations) == 1
    assert authorisations[0]["identityId"] == client.identity.identity_id
    assert authorisations[0]["protocolId"] == client.identity.private_key.protocol.name


@pytest.mark.parametrize("entity", entities)
def test_authorisations_signature(
    client: Client, mocked_requests_200: respx.MockTransport, entity: Entity
) -> None:
    """Signature of x-iov42-authorisations header is the signed request content."""
    _ = client.put(entity)

    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    authorisations = json.loads(
        iov42_decode(http_request.headers["x-iov42-authorisations"].encode())
    )
    try:
        content = http_request.read()
        client.identity.verify_signature(authorisations[0]["signature"], content)
    except InvalidSignature:
        pytest.fail("Signature verification failed")


@pytest.mark.parametrize("entity", entities)
def test_authentication_header(
    client: Client, mocked_requests_200: respx.MockTransport, entity: Entity
) -> None:
    """If x-iov42-authentication header is signed by the client's identity."""
    _ = client.put(entity)

    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    authentication = json.loads(
        iov42_decode(http_request.headers["x-iov42-authentication"].encode())
    )
    assert authentication["identityId"] == client.identity.identity_id
    assert authentication["protocolId"] == client.identity.private_key.protocol.name


@pytest.mark.parametrize("entity", entities)
def test_create_identity_authentication_header_signature(
    client: Client, mocked_requests_200: respx.MockTransport, entity: Entity
) -> None:
    """Signature of x-iov42-authentication header is the signed authorisations header."""
    _ = client.put(entity)

    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    authorisations_signatures = ";".join(
        [
            s["signature"]
            for s in json.loads(
                iov42_decode(http_request.headers["x-iov42-authorisations"].encode())
            )
        ]
    ).encode()
    authentication = json.loads(
        iov42_decode(http_request.headers["x-iov42-authentication"].encode())
    )
    try:
        client.identity.verify_signature(
            authentication["signature"], authorisations_signatures
        )
    except InvalidSignature:
        pytest.fail("Signature verification failed")


@pytest.mark.parametrize("entity", entities)
def test_claims_header(
    client: Client, mocked_requests_200: respx.MockTransport, entity: Entity
) -> None:
    """Request to create claims against an entity contains 'x-iov42-claims' header."""
    claim = Claim(b"claim-1")
    _ = client.put(entity, claims=[claim.data])
    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    claims_header = json.loads(iov42_decode(http_request.headers["x-iov42-claims"]))
    assert claims_header == {claim.hash: claim.data.decode()}


@pytest.mark.parametrize("entity", entities)
def test_create_endorsements_header(
    client: Client, mocked_requests_200: respx.MockTransport, entity: Entity
) -> None:
    """Request to create endorsements against an entity contains 'x-iov42-claims' header."""
    claim = Claim(b"claim-1")
    _ = client.put(entity, claims=[claim.data], endorse=True)
    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    claims_header = json.loads(iov42_decode(http_request.headers["x-iov42-claims"]))
    assert claims_header == {claim.hash: claim.data.decode()}


# TODO: this would still fail since the request is sent with the
# client.identity (having a different key). We takle this when we implement the
# creation of a delegated identity.
# Note: we want to enforce that each identity uses its own client instance.
@pytest.mark.skip(reason="to decide what we do")
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


# Responses to the PUT request


@pytest.mark.parametrize("entity", entities)
def test_response(
    client: Client, mocked_requests_200: respx.MockTransport, entity: Entity
) -> None:
    """Platform response to the create an entity request."""
    request_id = str(uuid.uuid4())
    response = client.put(entity, request_id=request_id)
    assert response.proof == "/api/v1/proofs/" + request_id
    assert len(response.resources) == 1  # type: ignore[union-attr]


def test_response_identity(
    client: Client,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """Platform response to the request to create an identity."""
    response = client.put(client.identity)
    assert response.resources == [  # type: ignore[union-attr]
        "/api/v1/identities/" + client.identity.identity_id
    ]


def test_response_asset_type(
    client: Client,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """Platform response to the request to create an asset type."""
    entity = AssetType()
    response = client.put(entity)
    assert response.resources == ["/api/v1/asset-types/" + entity.asset_type_id]  # type: ignore[union-attr]


def test_response_asset(
    client: Client,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """Platform response to the request to create an asset type."""
    entity = Asset(asset_type_id=str(uuid.uuid4()))
    response = client.put(entity)
    assert response.resources == [  # type: ignore[union-attr]
        "/".join(
            ("/api/v1/asset-types", entity.asset_type_id, "assets", entity.asset_id)
        )
    ]


# TODO: reponse to create (identity, asset type and asset) claims
# TODO: reponse to create (identity, asset type and asset) endorsements

# Error handling on the client side


@respx.mock
@pytest.mark.parametrize(
    "invalid_request_id",
    [("request-€"), ("%-request"), ("request-/")],
)
def test_invalid_request_id(client: Client, invalid_request_id: str) -> None:
    """Raise exception if the provided request ID contains invalid charatcers."""
    with pytest.raises(ValueError) as excinfo:
        client.put(client.identity, request_id=invalid_request_id)
    # No request is sent
    assert not respx.calls
    assert (
        str(excinfo.value)
        == f"invalid identifier '{invalid_request_id}' - valid characters are [a-zA-Z0-9._\\-+]"
    )


@pytest.mark.skip(reason="not implemented - check on valid quantity")
@pytest.mark.parametrize("invalid_quantity", ["invalid", ""])
def test_raises_invalid_quantity(
    client: Client, invalid_quantity: typing.Union[str, int]
) -> None:
    """Request content to create claims on an unique asset."""
    with pytest.raises(ValueError) as excinfo:
        client.put(Asset(asset_type_id="123456"), quantity=invalid_quantity)
    assert str(excinfo.value) == "whatever"


@pytest.mark.parametrize("entity", entities)
def test_raises_claims_missing(client: Client, entity: Entity) -> None:
    """Raise TyepError if no claims are provided for endorsement."""
    with pytest.raises(TypeError) as excinfo:
        client.put(entity, endorse=True)
    assert (
        str(excinfo.value)
        == "missing required keyword argument needed for endorsement: 'claims'"
    )
