"""Test cases with focus AssetType entities."""
import json
import typing
import uuid

import pytest

from iov42.core import AssetType
from iov42.core import hashed_claim
from iov42.core import PrivateIdentity


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


@pytest.mark.parametrize("scale", [0, 0.0, 2, "5"])
def test_quantifiable_asset_type(scale: typing.Union[str, int]) -> None:
    """Create quantifiable asset type."""
    asset_type = AssetType(scale=scale)  # type: ignore[arg-type]
    assert asset_type.scale == int(scale)


@pytest.mark.parametrize("invalid_scale", ["not an int", "", -1, 2.3, "5.5"])
def test_raises_value_error(invalid_scale: typing.Union[int, str, float]) -> None:
    """Raises ValueError on an invalid scale value."""
    with pytest.raises(ValueError) as excinfo:
        AssetType(scale=invalid_scale)  # type: ignore[arg-type]
    assert str(excinfo.value) == f"must be a whole, positive number: '{invalid_scale}'"


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


def test_create_unique_asset_type_content() -> None:
    """Request content to create an unique asset type."""
    request_id = "123456"
    asset_type = AssetType("987654")

    content = json.loads(asset_type.put_request_content(request_id=request_id))
    assert content == {
        "_type": "DefineAssetTypeRequest",
        "assetTypeId": asset_type.asset_type_id,
        "type": "Unique",
        "requestId": request_id,
    }


def test_create_quantifiable_asset_type_content() -> None:
    """Request content to create a quantifiable asset type."""
    request_id = "123456"
    asset_type = AssetType("123456", scale=2)

    content = json.loads(asset_type.put_request_content(request_id=request_id))
    assert content == {
        "_type": "DefineAssetTypeRequest",
        "assetTypeId": asset_type.asset_type_id,
        "type": "Quantifiable",
        "scale": 2,
        "requestId": request_id,
    }


def test_create_asset_type_claims_content() -> None:
    """Request content to create claims on an asset type."""
    request_id = "123456"
    claims = [b"claim-1", b"claim-2"]
    asset_type = AssetType("123456")

    content = json.loads(
        asset_type.put_request_content(request_id=request_id, claims=claims)
    )

    hashed_claims = content.pop("claims")
    assert content == {
        "_type": "CreateAssetTypeClaimsRequest",
        "subjectId": asset_type.asset_type_id,
        "requestId": request_id,
    }
    assert len(hashed_claims) == len(claims)
    for hc in [hashed_claim(c) for c in claims]:
        assert hc in hashed_claims


def test_create_asset_type_endorsements_content(identity: PrivateIdentity) -> None:
    """Request content to create claims and endorsements for an asset type."""
    request_id = "123456"
    claims = [b"claim-1", b"claim-2"]
    asset_type = AssetType("123456")

    content = json.loads(
        asset_type.put_request_content(
            request_id=request_id, claims=claims, endorser=identity
        )
    )

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
