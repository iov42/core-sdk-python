"""Test cases for request entity."""
import json
import uuid
from typing import Union

import pytest

from iov42.core import Asset
from iov42.core import AssetType
from iov42.core import CryptoProtocol
from iov42.core import Identity
from iov42.core import InvalidSignature
from iov42.core import Request
from iov42.core._crypto import iov42_decode
from iov42.core._entity import Claim
from iov42.core._entity import Operation
from iov42.core._entity import Response

entites = [
    (Identity(CryptoProtocol.SHA256WithECDSA.generate_private_key())),
    (AssetType()),
    (Asset(AssetType())),
]


def test_request_with_id() -> None:
    """Request with value."""
    request = Request(Operation.WRITE, AssetType(), id="123456")
    assert request.id == "123456"
    assert str(request) == "123456"


def test_generated_request() -> None:
    """Generated request is a UUID."""
    request = Request(Operation.READ, AssetType())
    assert uuid.UUID(str(request))


def test_no_xiov42_headers() -> None:
    """A newly created request does not contain any x-iov42 headers."""
    request = Request(Operation.WRITE, AssetType())
    assert request.headers == {"content-type": "application/json"}
    assert request.authorisations == []


# Note: identity is special.
@pytest.mark.parametrize("entity", entites)
def test_add_iov42_headers(
    identity: Identity, entity: Union[Identity, AssetType, Asset]
) -> None:
    """Content of x-iov42-authorisations header to create an identiy."""
    request = Request(Operation.WRITE, entity)
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
def test_authorisations_header(
    identity: Identity, entity: Union[Identity, AssetType, Asset]
) -> None:
    """Content of x-iov42-authorisations header to create an identiy."""
    request = Request(Operation.WRITE, entity)
    request.add_authentication_header(identity)

    authorisations = json.loads(iov42_decode(request.headers["x-iov42-authorisations"]))
    assert len(authorisations) == 1
    assert authorisations[0]["identityId"] == identity.id
    assert authorisations[0]["protocolId"] == identity.private_key.protocol.name


@pytest.mark.parametrize("entity", entites)
def test_authorisations_signature(
    identity: Identity, entity: Union[Identity, AssetType, Asset]
) -> None:
    """Content of x-iov42-authorisations header to create an identiy."""
    request = Request(Operation.WRITE, entity)
    request.add_authentication_header(identity)
    authorisations = json.loads(iov42_decode(request.headers["x-iov42-authorisations"]))

    try:
        identity.verify_signature(authorisations[0]["signature"], request.content)
    except InvalidSignature:
        pytest.fail("Signature verification failed")


@pytest.mark.parametrize("entity", entites)
def test_create_asset_type_authentication_header(
    identity: Identity, entity: Union[Identity, AssetType, Asset]
) -> None:
    """Content of x-iov42-authentication header to create an entity."""
    request = Request(Operation.WRITE, entity)
    request.add_authentication_header(identity)
    authentication = json.loads(iov42_decode(request.headers["x-iov42-authentication"]))

    assert authentication["identityId"] == identity.id


def test_create_asset_claims_and_endorsements_content(identity: Identity) -> None:
    """Request content to create claims and endorsements for an unique asset."""
    request_id = "123456"
    claim = b"claim-1"
    asset = Asset(AssetType())
    request = Request(
        Operation.WRITE, asset, id=request_id, claims=[claim], endorser=identity
    )
    content = json.loads(request.content)
    # Signatures are always different, we have to verify the signature
    endorsements = content.pop("endorsements")
    assert content == {
        "_type": "CreateAssetEndorsementsRequest",
        "subjectId": asset.id,
        "subjectTypeId": asset.asset_type.id,
        "endorserId": identity.id,
        "requestId": request_id,
    }
    for c, s in endorsements.items():
        identity.verify_signature(s, ";".join((asset.id, asset.asset_type.id, c)))


def test_create_asset_claims_header(identity: Identity) -> None:
    """Request content to create claims and endorsements for an unique asset."""
    claim = Claim(b"claim-1")
    request = Request(
        Operation.WRITE, Asset(AssetType()), claims=[claim.data], endorser=identity
    )
    claims = json.loads(iov42_decode(request.headers["x-iov42-claims"]))
    assert claims == {claim.hash: claim.data.decode()}


# TODO: test this also with asset_types and idenities
def test_raises_claims_missing(identity: Identity) -> None:
    """Raise TyepError if no claims are provided for endorsement."""
    with pytest.raises(TypeError) as excinfo:
        Request(Operation.WRITE, Asset(AssetType()), endorser=identity)
    assert (
        str(excinfo.value)
        == "missing required argument needed for endorsement: 'claims'"
    )


def test_request_repr() -> None:
    """Printable representation of a request."""
    # TODO: what information do we want to show in here?
    entity = Request(Operation.READ, AssetType(), id="123456")
    assert repr(entity) == "Request(id=123456)"


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
