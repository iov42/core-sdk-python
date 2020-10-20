"""Tests for asset entites."""
import hashlib
import uuid

import pytest

from iov42.core import Asset
from iov42.core._crypto import iov42_encode
from iov42.core._entity import Claim


def test_asset_generated_id() -> None:
    """Asset with no ID generates an UUID as ID."""
    asset = Asset(asset_type_id="123456")
    assert uuid.UUID(asset.asset_id)
    assert asset.asset_type_id == "123456"


def test_asset_with_id() -> None:
    """Provide asset ID explicitely."""
    asset = Asset(asset_id="98765", asset_type_id="123456")
    assert asset.asset_id == "98765"
    assert asset.asset_type_id == "123456"


@pytest.mark.parametrize("invalid_id", [("id-€"), ("%-id"), ("id-/")])
def test_raise_invalid_asset_id(invalid_id: str) -> None:
    """Raise exception if the provided id contains invalid charatcers."""
    with pytest.raises(ValueError) as excinfo:
        Asset(asset_id=invalid_id, asset_type_id="123456")
    assert (
        str(excinfo.value)
        == f"invalid identifier '{invalid_id}' - valid characters are [a-zA-Z0-9._\\-+]"
    )


@pytest.mark.parametrize("invalid_id", [("id-€"), ("%-id"), ("id-/"), ("")])
def test_raise_invalid_asset_type_id(invalid_id: str) -> None:
    """Raise exception if the provided id contains invalid charatcers."""
    with pytest.raises(ValueError) as excinfo:
        Asset(asset_id="98765", asset_type_id=invalid_id)
    assert (
        str(excinfo.value)
        == f"invalid identifier '{invalid_id}' - valid characters are [a-zA-Z0-9._\\-+]"
    )


def test_claim() -> None:
    """Hash of a claim."""
    claim = Claim(b"claim-1")
    assert claim.data == b"claim-1"
    assert claim.hash == iov42_encode(hashlib.sha256(b"claim-1").digest()).decode()


def test_relative_path() -> None:
    """Return relative URL where the asset information can be read."""
    asset = Asset(asset_type_id="123456")
    assert asset.resource == "/".join(
        ("/api/v1/asset-types", asset.asset_type_id, "assets", asset.asset_id)
    )
