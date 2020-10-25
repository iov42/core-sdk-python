"""Tests for asset entites."""
import hashlib
import uuid

import pytest

from iov42.core import Asset
from iov42.core import AssetType
from iov42.core._crypto import iov42_encode
from iov42.core._entity import Claim


def test_asset() -> None:
    """Provide only asset type."""
    asset_type = AssetType()
    asset = Asset(asset_type)
    assert uuid.UUID(asset.id)
    assert asset.asset_type == asset_type


# TODO: this is really confusing. Why is the strting provided not the asset id?
# We probably should provide all entity attributes explicitely.
def test_asset_with_str() -> None:
    """Provide asset type as string."""
    asset = Asset("123456")
    assert asset.asset_type.id == "123456"
    assert uuid.UUID(asset.id)


def test_asset_with_id() -> None:
    """Provide asset id explictely."""
    asset_type = AssetType()
    asset = Asset(asset_type, "123456")
    assert asset.id == "123456"


@pytest.mark.parametrize("invalid_id", [("id-€"), ("%-id"), ("id-/")])
def test_raise_invalid_id(invalid_id: str) -> None:
    """Raise exception if the provided id contains invalid charatcers."""
    with pytest.raises(ValueError) as excinfo:
        Asset(AssetType(), invalid_id)
    assert (
        str(excinfo.value)
        == f"invalid identifier '{invalid_id}' - valid characters are [a-zA-Z0-9._\\-+]"
    )


def test_claim() -> None:
    """Hash of a claim."""
    claim = Claim(b"claim-1")
    assert claim.data == b"claim-1"
    assert claim.hash == iov42_encode(hashlib.sha256(b"claim-1").digest()).decode()
