"""Test cases for working with iov42 identities."""
import uuid

import pytest

from iov42.core import CryptoProtocol
from iov42.core import Identity
from iov42.core import PrivateKey
from iov42.core._entity import Entity


def test_entity() -> None:
    """Create entity with ID."""
    entity = Entity("123456")
    assert entity.id == "123456"


def test_entity_id_generation() -> None:
    """Create ID is a UUID string."""
    entity = Entity()
    assert uuid.UUID(entity.id)


def test_entity_str() -> None:
    """Tests creation of an entity."""
    entity = Entity("123456")
    assert str(entity) == "123456"


def test_entity_repr() -> None:
    """Printable representation of an entity."""
    entity = Entity("123456")
    assert repr(entity) == "Entity(id=123456)"


@pytest.mark.parametrize(
    "invalid_id",
    [("1234-€"), ("%-12345"), ("12345-/"), ("12345 567")],
)
def test_invalid_entity_id(invalid_id: str) -> None:
    """Raises ValueError in case the provided ID is invalid."""
    with pytest.raises(ValueError) as excinfo:
        Entity(invalid_id)
    assert (
        str(excinfo.value)
        == f"invalid identifier '{invalid_id}' - valid characters are [a-zA-Z0-9._\\-+]"
    )


def test_identity() -> None:
    """Creates identity with ID."""
    idenity = Identity(CryptoProtocol.SHA256WithRSA.generate_private_key(), "1234567")
    assert idenity.identity_id == "1234567"
    assert isinstance(idenity.private_key, PrivateKey)


def test_identity_raises_typerror() -> None:
    """Raise TypeError in case no private key is ptovided."""
    with pytest.raises(TypeError) as excinfo:
        Identity("123456")  # type: ignore[arg-type]
    assert str(excinfo.value) == "must be PrivateKey, not str"


def test_identity_default_uuid() -> None:
    """Generated ID is an UUID."""
    identity = Identity(CryptoProtocol.SHA256WithECDSA.generate_private_key())
    assert uuid.UUID(identity.identity_id)


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
