"""Test cases for request entity."""
import json
import uuid

import pytest

from iov42.core import Asset
from iov42.core import AssetType
from iov42.core import CryptoProtocol
from iov42.core import Entity
from iov42.core import Identity
from iov42.core import InvalidSignature
from iov42.core import Request
from iov42.core._crypto import iov42_decode
from iov42.core._entity import Claim

entites = [
    (Identity(CryptoProtocol.SHA256WithECDSA.generate_private_key())),
    (AssetType()),
    (Asset(asset_type_id="123456")),
]


def test_request_with_id() -> None:
    """Request with value."""
    request = Request("PUT", "https://example.org", AssetType(), request_id="123456")
    assert request.resource == "/api/v1/requests/123456"
    assert request.url == "https://example.org/api/v1/requests/123456"


def test_request_url_with_path() -> None:
    """Request with value."""
    request = Request(
        "PUT", "https://example.org/test", AssetType(), request_id="98765"
    )
    assert request.resource == "/api/v1/requests/98765"
    assert request.url == "https://example.org/test/api/v1/requests/98765"


def test_generated_request_id() -> None:
    """Generated request is a UUID."""
    request = Request("PUT", "https://example.org", AssetType())
    assert uuid.UUID(request.url.rsplit("/", 1)[1])


def test_no_xiov42_headers() -> None:
    """A newly created request does not contain any x-iov42 headers."""
    request = Request("PUT", "https://example.org", AssetType())
    assert [*request.headers] == ["content-type"]
    assert request.authorisations == []


@pytest.mark.parametrize("entity", entites)
def test_add_iov42_headers(identity: Identity, entity: Entity) -> None:
    """Authentication adds neccessary x-iov42 headers signed by the identity."""
    request = Request("PUT", "https://example.org", entity)
    request.add_authentication_header(identity)
    assert [*request.headers] == [
        "content-type",
        "x-iov42-authorisations",
        "x-iov42-authentication",
    ]


# TODO: the created identity is signed with client.identity which would not
# work. Look into this when we have to use case to add an authorisation of a 2nd
# identity.
@pytest.mark.parametrize("entity", entites)
def test_authorisations_header_content(identity: Identity, entity: Entity) -> None:
    """Content of x-iov42-authorisations header to create an identiy."""
    request = Request("PUT", "https://example.org", entity)
    request.add_authentication_header(identity)

    authorisations = json.loads(iov42_decode(request.headers["x-iov42-authorisations"]))
    assert len(authorisations) == 1
    assert authorisations[0]["identityId"] == identity.identity_id
    assert authorisations[0]["protocolId"] == identity.private_key.protocol.name


@pytest.mark.parametrize("entity", entites)
def test_authorisations_header_signature(identity: Identity, entity: Entity) -> None:
    """Signature of x-iov42-authorisations header was signed by request."""
    request = Request("PUT", "https://example.org", entity)
    request.add_authentication_header(identity)
    authorisations = json.loads(iov42_decode(request.headers["x-iov42-authorisations"]))

    try:
        identity.verify_signature(authorisations[0]["signature"], request.content)
    except InvalidSignature:
        pytest.fail("Signature verification failed")


@pytest.mark.parametrize("entity", entites)
def test_create_asset_type_authentication_header(
    identity: Identity, entity: Entity
) -> None:
    """Content of x-iov42-authentication header to create an entity."""
    request = Request("PUT", "https://example.org", entity)
    request.add_authentication_header(identity)
    authentication = json.loads(iov42_decode(request.headers["x-iov42-authentication"]))

    assert authentication["identityId"] == identity.identity_id


def test_create_asset_type_claim_content() -> None:
    """Request content to create claims on an asset type."""
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
    hashed_claims = content.pop("claims")
    assert content == {
        "_type": "CreateAssetTypeClaimsRequest",
        "subjectId": asset_type.asset_type_id,
        "requestId": request_id,
    }
    assert len(hashed_claims) == len(claims)
    for hc in [Claim(c) for c in claims]:
        assert hc.hash in hashed_claims


def test_create_asset_type_claims_and_endorsements_content(identity: Identity) -> None:
    """Request content to create claims and endorsements for an asset type."""
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
    # Signatures are always different, we have to verify the signature
    endorsements = content.pop("endorsements")
    assert content == {
        "_type": "CreateAssetTypeEndorsementsRequest",
        "subjectId": asset_type.asset_type_id,
        "endorserId": identity.identity_id,
        "requestId": request_id,
    }
    for c, s in endorsements.items():
        identity.verify_signature(s, ";".join((asset_type.asset_type_id, c)).encode())


def test_create_asset_claims_header(identity: Identity) -> None:
    """Request content to create claims and endorsements for an unique asset."""
    claim = Claim(b"claim-1")
    request = Request(
        "PUT",
        "https://example.org",
        Asset(asset_type_id="123456"),
        claims=[claim.data],
        endorser=identity,
    )
    claims = json.loads(iov42_decode(request.headers["x-iov42-claims"]))
    assert claims == {claim.hash: claim.data.decode()}


def test_create_asset_claim_content() -> None:
    """Request content to create claims on an unique asset."""
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
    hashed_claims = content.pop("claims")
    assert content == {
        "_type": "CreateAssetClaimsRequest",
        "subjectId": asset.asset_id,
        "subjectTypeId": asset.asset_type_id,
        "requestId": request_id,
    }
    assert len(hashed_claims) == len(claims)
    for hc in [Claim(c) for c in claims]:
        assert hc.hash in hashed_claims


def test_create_asset_claims_and_endorsements_content(identity: Identity) -> None:
    """Request content to create claims and endorsements for an unique asset."""
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
    # Signatures are always different, we have to verify the signature
    endorsements = content.pop("endorsements")
    assert content == {
        "_type": "CreateAssetEndorsementsRequest",
        "subjectId": asset.asset_id,
        "subjectTypeId": asset.asset_type_id,
        "endorserId": identity.identity_id,
        "requestId": request_id,
    }
    for c, s in endorsements.items():
        identity.verify_signature(
            s, ";".join((asset.asset_id, asset.asset_type_id, c)).encode()
        )


# TODO: test this also with asset_types and idenities
def test_raises_claims_missing(identity: Identity) -> None:
    """Raise TyepError if no claims are provided for endorsement."""
    with pytest.raises(TypeError) as excinfo:
        Request(
            "PUT",
            "https://example.org",
            Asset(asset_type_id="123456"),
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
