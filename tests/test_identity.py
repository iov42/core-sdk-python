"""Test cases for working with iov42 identities."""
import json
import uuid

import pytest

from iov42.core import CryptoProtocol
from iov42.core import hashed_claim
from iov42.core import Identity
from iov42.core import PrivateKey


def test_identity() -> None:
    """Creates identity with ID."""
    idenity = Identity(
        CryptoProtocol.SHA256WithRSA.generate_private_key(), identity_id="1234567"
    )
    assert idenity.identity_id == "1234567"
    assert isinstance(idenity.private_key, PrivateKey)


def test_identity_generated_id() -> None:
    """Generated ID is an UUID."""
    identity = Identity(CryptoProtocol.SHA256WithECDSA.generate_private_key())
    assert uuid.UUID(identity.identity_id)


def test_repr() -> None:
    """Informal representation of an idenity."""
    identity = Identity(CryptoProtocol.SHA256WithECDSA.generate_private_key())
    assert repr(identity) == f"Identity(identity_id='{identity.identity_id}')"


def test_relative_path() -> None:
    """Relative path of a created identity."""
    identity = Identity(CryptoProtocol.SHA256WithECDSA.generate_private_key())
    assert identity.resource == "/".join(("/api/v1/identities", identity.identity_id))


def test_identity_raises_typerror() -> None:
    """Raise TypeError in case no private key is ptovided."""
    with pytest.raises(TypeError) as excinfo:
        Identity("123456")  # type: ignore[arg-type]
    assert str(excinfo.value) == "must be PrivateKey, not str"


@pytest.mark.parametrize(
    "invalid_id",
    [("1234-€"), ("%-12345"), ("12345-/"), ("12345 567")],
)
def test_invalid_identity_id(invalid_id: str) -> None:
    """Raises ValueError in case the provided ID is invalid."""
    with pytest.raises(ValueError) as excinfo:
        Identity(CryptoProtocol.SHA256WithECDSA.generate_private_key(), invalid_id)
    assert (
        str(excinfo.value)
        == f"invalid identifier '{invalid_id}' - valid characters are [a-zA-Z0-9._\\-+]"
    )


def test_create_identity_content(identity: Identity) -> None:
    """Request content to create an identity."""
    request_id = "123456"

    content = json.loads(identity.put_request_content(request_id=request_id))

    assert content == {
        "_type": "IssueIdentityRequest",
        "requestId": request_id,
        "identityId": identity.identity_id,
        "publicCredentials": {
            "protocolId": identity.private_key.protocol.name,
            "key": identity.private_key.public_key().dump(),
        },
    }


def test_create_identity_claim_content(identity: Identity) -> None:
    """Request content to create claims against an identity."""
    request_id = "123456"
    claims = [b"claim-1", b"claim-2"]

    content = json.loads(
        identity.put_request_content(request_id=request_id, claims=claims)
    )

    hashed_claims = content.pop("claims")
    assert content == {
        "_type": "CreateIdentityClaimsRequest",
        "subjectId": identity.identity_id,
        "requestId": request_id,
    }
    assert len(hashed_claims) == len(claims)
    for hc in [hashed_claim(c) for c in claims]:
        assert hc in hashed_claims


def test_create_identity_endorsements_content(identity: Identity) -> None:
    """Request type to create claims and endorsements against an identity."""
    request_id = "123456"
    claims = [b"claim-1", b"claim-2"]

    content = json.loads(
        identity.put_request_content(
            request_id=request_id, claims=claims, endorser=identity
        )
    )

    # Signatures are always different, we have to verify the signature
    endorsements = content.pop("endorsements")
    assert content == {
        "_type": "CreateIdentityEndorsementsRequest",
        "subjectId": identity.identity_id,
        "endorserId": identity.identity_id,
        "requestId": request_id,
    }
    for c, s in endorsements.items():
        identity.verify_signature(s, ";".join((identity.identity_id, c)).encode())
