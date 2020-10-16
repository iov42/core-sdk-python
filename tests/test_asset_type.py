"""Tests AssetType."""
import uuid

import pytest

from iov42.core import AssetType


def test_generate_unique_asset_type() -> None:
    """Generated AssetType is a UUID."""
    asset_type = AssetType()
    assert uuid.UUID(str(asset_type))
    assert asset_type.type == "Unique"


def test_create_unique_asset_type() -> None:
    """Create unique asset type wih desired ID."""
    asset_type = AssetType("12345")
    assert asset_type.id == "12345"
    assert asset_type.type == "Unique"


def test_asset_type_str() -> None:
    """Informal representation of asset type."""
    asset_type = AssetType()
    assert str(asset_type) == asset_type.id


def test_asset_type_repr() -> None:
    """Printable representation of asset type."""
    asset_type = AssetType("12345")
    assert repr(asset_type) == "AssetType(id=12345,type=Unique)"


@pytest.mark.parametrize(
    "invalid_id",
    [("1234-€"), ("%-12345"), ("12345-/"), ("12345 567")],
)
def test_invalid_id(invalid_id: str) -> None:
    """Raises ValueError in case the provided ID is invalid."""
    with pytest.raises(ValueError) as excinfo:
        AssetType(invalid_id)
    assert (
        str(excinfo.value)
        == f"invalid identifier '{invalid_id}' - valid characters are [a-zA-Z0-9._\\-+]"
    )
    pass
