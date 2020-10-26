"""Tests AssetType."""
import uuid

import pytest

from iov42.core import AssetType


def test_create_unique_asset_type() -> None:
    """Create unique asset type wih desired ID."""
    asset_type = AssetType(asset_type_id="12345")
    assert asset_type.asset_type_id == "12345"
    assert asset_type.type == "Unique"


def test_generate_unique_asset_type() -> None:
    """Asset type with no ID generates an UUID as ID."""
    asset_type = AssetType()
    assert uuid.UUID(asset_type.asset_type_id)


def test_asset_type_repr() -> None:
    """Informal representation of asset type."""
    asset_type = AssetType()
    assert repr(asset_type) == f"AssetType(asset_type_id='{asset_type.asset_type_id}')"


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


def test_relative_path() -> None:
    """Return relative URL where the asset type information can be read."""
    asset = AssetType()
    assert asset.resource == "/".join(("/api/v1/asset-types", asset.asset_type_id))
