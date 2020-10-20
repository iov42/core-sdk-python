"""Test cases for working with iov42 identities."""
import uuid

import pytest

from iov42.core import CryptoProtocol
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
