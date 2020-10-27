"""Test cases for creating PUT requests."""
import json
import typing
import uuid

import pytest

from iov42.core import Asset
from iov42.core import AssetType
from iov42.core import CryptoProtocol
from iov42.core import Entity
from iov42.core import Identity
from iov42.core import Request

entities = [
    (Identity(CryptoProtocol.SHA256WithECDSA.generate_private_key())),
    (AssetType()),
    (Asset(asset_type_id="123456")),
]


def id_class_name(value: typing.Any) -> str:
    """Provide class name for test identifier."""
    return str(value.__class__.__name__)


@pytest.mark.parametrize("entity", entities, ids=id_class_name)
def test_request_with_id(entity: Entity) -> None:
    """Request with value."""
    request = Request("PUT", "https://example.org", entity, request_id="123456")
    assert request.resource == "/api/v1/requests/123456"
    assert request.url == "https://example.org/api/v1/requests/123456"


@pytest.mark.parametrize("entity", entities, ids=id_class_name)
def test_request_url_with_path(entity: Entity) -> None:
    """Request with URL having a path."""
    request = Request("PUT", "https://example.org/test", entity, request_id="98765")
    assert request.resource == "/api/v1/requests/98765"
    assert request.url == "https://example.org/test/api/v1/requests/98765"


@pytest.mark.parametrize("entity", entities, ids=id_class_name)
def test_generated_request_id(entity: Entity) -> None:
    """Generated request is a UUID."""
    request = Request("PUT", "https://example.org", entity)
    assert uuid.UUID(request.url.rsplit("/", 1)[1])


@pytest.mark.parametrize("entity", entities, ids=id_class_name)
def test_no_xiov42_headers(entity: Entity) -> None:
    """A newly created request does not contain any x-iov42 headers."""
    request = Request("PUT", "https://example.org", entity)
    assert [*request.headers] == ["content-type"]
    assert request.authorisations == []


@pytest.mark.parametrize("entity", entities, ids=id_class_name)
def test_add_iov42_headers(identity: Identity, entity: Entity) -> None:
    """Authentication adds neccessary x-iov42 headers signed by the identity."""
    request = Request("PUT", "https://example.org", entity)
    request.add_authentication_header(identity)
    assert [*request.headers] == [
        "content-type",
        "x-iov42-authorisations",
        "x-iov42-authentication",
    ]


@pytest.mark.parametrize("entity", entities, ids=id_class_name)
def test_authorised_by(identity: Identity, entity: Entity) -> None:
    """Add authorization by an identity."""
    request = Request("PUT", "https://example.org", entity)
    request.authorised_by(identity)
    assert [*request.headers] == ["content-type"]
    assert len(request.authorisations) == 1
    assert request.authorisations[0]["identityId"] == identity.identity_id
    assert request.authorisations[0]["protocolId"] == identity.private_key.protocol.name


@pytest.mark.parametrize("entity", entities, ids=id_class_name)
def test_authorised_by_idempotent(identity: Identity, entity: Entity) -> None:
    """Authoriation is only added once per identity."""
    request = Request("PUT", "https://example.org", entity)
    request.authorised_by(identity)
    request.authorised_by(identity)
    assert len(request.authorisations) == 1


@pytest.mark.parametrize("entity", entities, ids=id_class_name)
def test_authorised_by_on_get_request(identity: Identity, entity: Entity) -> None:
    """Authorisation works only on PUT request."""
    request = Request("GET", "https://example.org", entity, node_id="node-1")
    with pytest.raises(AttributeError) as excinfo:
        request.authorised_by(identity)
    assert str(excinfo.value) == "'Request' object has no attribute 'authorisations'"


def test_issue_identity_request(identity: Identity) -> None:
    """Request type to issue an identity."""
    request_id = "123456"
    request = Request(
        "PUT",
        "https://example.org",
        identity,
        request_id=request_id,
    )

    content = json.loads(request.content)
    assert content["_type"] == "IssueIdentityRequest"


def test_create_identity_claim_request(identity: Identity) -> None:
    """Request type to create claims against an identity."""
    request_id = "123456"
    claims = [b"claim-1", b"claim-2"]
    request = Request(
        "PUT",
        "https://example.org",
        identity,
        request_id=request_id,
        claims=claims,
    )

    content = json.loads(request.content)
    assert content["_type"] == "CreateIdentityClaimsRequest"


def test_create_identity_endorsements_request(identity: Identity) -> None:
    """Request type to create endorsements against claims of an identity."""
    request_id = "123456"
    claims = [b"claim-1", b"claim-2"]
    request = Request(
        "PUT",
        "https://example.org",
        identity,
        request_id=request_id,
        claims=claims,
        endorser=identity,
    )
    content = json.loads(request.content)
    assert content["_type"] == "CreateIdentityEndorsementsRequest"


def test_define_asset_type_request() -> None:
    """Request type to create an unique asset type."""
    request_id = "123456"
    asset_type = AssetType("987654")

    request = Request(
        "PUT",
        "https://example.org",
        asset_type,
        request_id=request_id,
    )

    content = json.loads(request.content)
    assert content["_type"] == "DefineAssetTypeRequest"


def test_define_asset_type_request_quantifiable() -> None:
    """Request type to create a quantifiable asset type."""
    request_id = "123456"
    asset_type = AssetType("123456", scale=2)

    request = Request(
        "PUT",
        "https://example.org",
        asset_type,
        request_id=request_id,
    )

    content = json.loads(request.content)
    assert content["_type"] == "DefineAssetTypeRequest"


def test_create_asset_type_claims_request() -> None:
    """Request type to create claims against an asset type."""
    request_id = "123456"
    claims = [b"claim-1", b"claim-2"]
    asset_type = AssetType("123456")

    request = Request(
        "PUT",
        "https://example.org",
        asset_type,
        request_id=request_id,
        claims=claims,
    )

    content = json.loads(request.content)
    assert content["_type"] == "CreateAssetTypeClaimsRequest"


def test_create_asset_type_endorsements_request(identity: Identity) -> None:
    """Request type to create endorsements against claims of an asset type."""
    request_id = "123456"
    claims = [b"claim-1", b"claim-2"]
    asset_type = AssetType("123456")

    request = Request(
        "PUT",
        "https://example.org",
        asset_type,
        request_id=request_id,
        claims=claims,
        endorser=identity,
    )

    content = json.loads(request.content)
    assert content["_type"] == "CreateAssetTypeEndorsementsRequest"


def test_create_asset_request() -> None:
    """Request type to create an unique asset."""
    request_id = "123456"
    asset = Asset(asset_type_id="123456")
    request = Request(
        "PUT",
        "https://example.org",
        asset,
        request_id=request_id,
    )

    content = json.loads(request.content)
    assert content["_type"] == "CreateAssetRequest"


@pytest.mark.parametrize("quantity", [0, 100, "0", "300", 0.0, "30.0"])
def test_create_asset_request_account(quantity: typing.Union[str, int, float]) -> None:
    """Request type to create an account."""
    request_id = "123456"
    asset = Asset(asset_type_id="123456", quantity=quantity)  # type: ignore[arg-type]
    request = Request(
        "PUT",
        "https://example.org",
        asset,
        request_id=request_id,
    )

    content = json.loads(request.content)
    assert content["_type"] == "CreateAssetRequest"


@pytest.mark.parametrize("invalid_quantity", ["invalid", "", -1, 0.1])
def test_raises_invalid_quantity(invalid_quantity: typing.Union[str, int]) -> None:
    """Raises ValueError for invalid quantity."""
    with pytest.raises(ValueError) as excinfo:
        Request(
            "PUT",
            "https://example.org",
            Asset(asset_type_id="123456", quantity=invalid_quantity),  # type: ignore[arg-type]
        )
    assert (
        str(excinfo.value) == f"must be a whole, positive number: '{invalid_quantity}'"
    )


def test_create_asset_claims_request() -> None:
    """Request type to create claims on an unique asset."""
    request_id = "123456"
    claims = [b"claim-1", b"claim-2"]
    asset = Asset(asset_type_id="123456")
    request = Request(
        "PUT",
        "https://example.org",
        asset,
        request_id=request_id,
        claims=claims,
    )

    content = json.loads(request.content)
    assert content["_type"] == "CreateAssetClaimsRequest"


def test_create_asset_endorsements_request(identity: Identity) -> None:
    """Request type to create claims and endorsements for an unique asset."""
    request_id = "123456"
    claim = b"claim-1"
    asset = Asset(asset_type_id="123456")
    request = Request(
        "PUT",
        "https://example.org",
        asset,
        request_id=request_id,
        claims=[claim],
        endorser=identity,
    )
    content = json.loads(request.content)
    assert content["_type"] == "CreateAssetEndorsementsRequest"


@pytest.mark.parametrize("entity", entities, ids=id_class_name)
def test_raises_claims_missing(identity: Identity, entity: Entity) -> None:
    """Raise TyepError if no claims are provided for endorsement."""
    with pytest.raises(TypeError) as excinfo:
        Request(
            "PUT",
            "https://example.org",
            entity,
            endorser=identity,
        )
    assert (
        str(excinfo.value)
        == "missing required keyword argument needed for endorsement: 'claims'"
    )


def test_unknown_method(identity: Identity) -> None:
    """We create the request even if the method is bogus."""
    request = Request(
        "FOO",
        "https://example.org",
        Asset(asset_type_id="123456"),
    )
    request.add_authentication_header(identity)
    assert [*request.headers] == []
    assert request.url == "https://example.org"
    assert request.content == b""
    assert not hasattr(request, "resource")
