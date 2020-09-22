"""Test cases for working with iov42 identities."""
import json
import typing
import uuid

import pytest

from iov42.core import CryptoProtocol
from iov42.core import hashed_claim
from iov42.core import PrivateIdentity
from iov42.core import PrivateKey
from iov42.core import PublicIdentity
from iov42.core import PublicKey


identities = [
    PrivateIdentity(
        CryptoProtocol.SHA256WithECDSA.generate_private_key(),
        identity_id="my.private.identity",
    ),
    PublicIdentity(identity_id="my.public.identity"),
]


def test_private_identity() -> None:
    """Creates private identity with ID."""
    identity = PrivateIdentity(
        CryptoProtocol.SHA256WithRSA.generate_private_key(), "1234567"
    )
    assert identity.identity_id == "1234567"
    assert isinstance(identity.private_key, PrivateKey)


def test_private_identity_with_delegate_identity_id() -> None:
    """Creates private identity with ID as a delegate."""
    identity = PrivateIdentity(
        CryptoProtocol.SHA256WithRSA.generate_private_key(), "1234567", "abcdefgh"
    )
    assert identity.identity_id == "1234567"
    assert isinstance(identity.private_key, PrivateKey)
    assert identity.delegate_identity_id == "abcdefgh"


def test_private_identity_converted_to_delegate() -> None:
    """Creates private identity and converts it to a delegate."""
    identity = PrivateIdentity(
        CryptoProtocol.SHA256WithRSA.generate_private_key(), "1234567"
    )
    delegate = identity.delegate_of("abcdefgh")
    assert delegate.identity_id == "1234567"
    assert isinstance(delegate.public_key, PublicKey)
    assert delegate.delegator_identity_id == "abcdefgh"


def test_private_identity_generated_id() -> None:
    """If no ID is provided generate an UUID as ID."""
    identity = PrivateIdentity(CryptoProtocol.SHA256WithECDSA.generate_private_key())
    assert uuid.UUID(identity.identity_id)


def test__private_identity_raises_typerror() -> None:
    """Raise TypeError in case no private key is provided."""
    with pytest.raises(TypeError) as excinfo:
        PrivateIdentity("123456")  # type: ignore[arg-type]
    assert str(excinfo.value) == "must be PrivateKey, not str"


@pytest.mark.parametrize(
    "invalid_id",
    [("1234-€"), ("%-12345"), ("12345-/"), ("12345 567")],
)
def test_private_identity_invalid_identity_id(invalid_id: str) -> None:
    """Raises ValueError in case the provided ID is invalid."""
    with pytest.raises(ValueError) as excinfo:
        PrivateIdentity(
            CryptoProtocol.SHA256WithECDSA.generate_private_key(), invalid_id
        )
    assert (
        str(excinfo.value)
        == f"invalid identifier '{invalid_id}' - valid characters are [a-zA-Z0-9._\\-+]"
    )


@pytest.mark.parametrize(
    "invalid_id",
    [("1234-€"), ("%-12345"), ("12345-/"), ("12345 567")],
)
def test_private_identity_invalid_delegate_identity_id(invalid_id: str) -> None:
    """Raises ValueError in case the provided ID is invalid."""
    with pytest.raises(ValueError) as excinfo:
        PrivateIdentity(
            CryptoProtocol.SHA256WithECDSA.generate_private_key(), "123456", invalid_id
        )
    assert (
        str(excinfo.value)
        == f"invalid identifier '{invalid_id}' - valid characters are [a-zA-Z0-9._\\-+]"
    )


def test_public_identity() -> None:
    """Public identity needs an ID."""
    identity = PublicIdentity("example.identity")
    assert identity.identity_id == "example.identity"


@pytest.mark.parametrize(
    "invalid_id",
    [("1234-€"), ("%-12345"), ("12345-/"), ("12345 567")],
)
def test_public_identity_invalid_identity_id(invalid_id: str) -> None:
    """Raises ValueError in case the provided ID is invalid."""
    with pytest.raises(ValueError) as excinfo:
        PublicIdentity(invalid_id)
    assert (
        str(excinfo.value)
        == f"invalid identifier '{invalid_id}' - valid characters are [a-zA-Z0-9._\\-+]"
    )


def test_public_identity_raises_no_identity_id() -> None:
    """Raises TypeError if the agruments are switched."""
    public_key = CryptoProtocol.SHA256WithECDSA.generate_private_key().public_key()

    with pytest.raises(TypeError) as excinfo:
        PublicIdentity(public_key)  # type: ignore[arg-type]
    assert str(excinfo.value) == "expected string or bytes-like object"


def test_public_identity_raises_switched_arguments() -> None:
    """Raises TypeError if the agruments are switched."""
    public_key = CryptoProtocol.SHA256WithECDSA.generate_private_key().public_key()

    with pytest.raises(TypeError) as excinfo:
        PublicIdentity(public_key, "example.identity")  # type: ignore[arg-type]
    assert str(excinfo.value) == "must be PublicKey, not str"


@pytest.mark.parametrize(
    "identity, expected_rep",
    list(
        zip(
            identities,
            [
                "PrivateIdentity(identity_id='my.private.identity', delegate_identity_id='')",
                "PublicIdentity(identity_id='my.public.identity', delegator_identity_id='')",
            ],
        )
    ),
)
def test_repr(
    identity: typing.Union[PrivateIdentity, PublicIdentity], expected_rep: str
) -> None:
    """Informal representation of an idenity."""
    assert repr(identity) == expected_rep


def test_relative_path() -> None:
    """Relative path of a created identity."""
    identity = PublicIdentity("1234567")
    assert identity.resource == "/".join(("/api/v1/identities", identity.identity_id))


def test_create_identity_content(public_identity: PublicIdentity) -> None:
    """Request content to create an identity."""
    request_id = "123456"

    content = json.loads(public_identity.put_request_content(request_id=request_id))

    public_key = typing.cast(PublicKey, public_identity.public_key)
    assert content == {
        "_type": "IssueIdentityRequest",
        "requestId": request_id,
        "identityId": public_identity.identity_id,
        "publicCredentials": {
            "protocolId": public_key.protocol.name,
            "key": public_key.dump(),
        },
    }


def test_put_request_content_raises_error_no_public_key() -> None:
    """Raise RuntimeError if the identity has no public key defined."""
    public_identity = PublicIdentity("no.public.key")

    with pytest.raises(RuntimeError) as excinf:
        public_identity.put_request_content()
    assert str(excinf.value) == "identity 'no.public.key' has no public key"


def test_create_identity_claim_content(public_identity: PublicIdentity) -> None:
    """Request content to create claims against an identity."""
    request_id = "123456"
    claims = [b"claim-1", b"claim-2"]

    content = json.loads(
        public_identity.put_request_content(request_id=request_id, claims=claims)
    )

    hashed_claims = content.pop("claims")
    assert content == {
        "_type": "CreateIdentityClaimsRequest",
        "subjectId": public_identity.identity_id,
        "requestId": request_id,
    }
    assert len(hashed_claims) == len(claims)
    for hc in [hashed_claim(c) for c in claims]:
        assert hc in hashed_claims


def test_create_identity_endorsements_content(identity: PrivateIdentity) -> None:
    """Request type to create claims and endorsements against an identity."""
    request_id = "123456"
    claims = [b"claim-1", b"claim-2"]

    content = json.loads(
        identity.public_identity.put_request_content(
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


def test_create_identity_add_delegate_content(identity: PrivateIdentity) -> None:
    """Request content to add a delegate to an identity."""
    delegate = identity.delegate_of("abcdefgh")
    bytes_content, authorisation = identity.sign_entity(delegate)

    content = json.loads(bytes_content)

    assert content["_type"] == "AddDelegateRequest"
    assert content["delegateIdentityId"] == delegate.identity_id
    assert content["delegatorIdentityId"] == delegate.delegator_identity_id


def test_verify_signature_raises_error_no_public_key() -> None:
    """Raise RuntimeError if the identity has no public key defined."""
    public_identity = PublicIdentity("no.public.key")

    with pytest.raises(RuntimeError) as excinf:
        public_identity.verify_signature("siganture", b"some data")
    assert str(excinf.value) == "identity 'no.public.key' has no public key"
