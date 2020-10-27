"""Tests for asset entites."""
import json
import typing
import uuid

import pytest

from iov42.core import Asset
from iov42.core import hashed_claim
from iov42.core import Identity


def test_asset() -> None:
    """Provide asset ID explicitely."""
    asset = Asset(asset_type_id="123456", asset_id="98765")
    assert asset.asset_id == "98765"
    assert asset.asset_type_id == "123456"


def test_asset_generated_id() -> None:
    """Asset with no ID generates an UUID as ID."""
    asset = Asset(asset_type_id="123456")
    assert uuid.UUID(asset.asset_id)


@pytest.mark.parametrize("quantity", [0, 0.0, 100, 200.0, "10", "20.0"])
def test_account(quantity: typing.Union[int, float, str]) -> None:
    """Create an account with initial quantity."""
    account = Asset(asset_type_id="98765", quantity=quantity)  # type: ignore[arg-type]
    assert account.quantity == str(int(float(quantity)))


def test_repr() -> None:
    """Informal representation of an asset."""
    asset = Asset(asset_type_id="123456")
    assert (
        repr(asset)
        == f"Asset(asset_type_id='{asset.asset_type_id}', asset_id='{asset.asset_id}')"
    )


@pytest.mark.parametrize("quantity", [0, 0.0, 100, 200.0, "10", "20.0"])
@pytest.mark.skip(reason="not implemented")
def test_rep_account(quantity: typing.Union[int, float, str]) -> None:
    """Informal representation of an account."""
    asset = Asset(asset_type_id="123456", quantity=quantity)  # type: ignore[arg-type]
    assert (
        repr(asset)
        == f"Asset(asset_type_id='{asset.asset_type_id}', asset_id='{asset.asset_id}',"
        f" quantity='{asset.quantity}'"
    )


@pytest.mark.parametrize("invalid_id", [("id-€"), ("%-id"), ("id-/"), ("")])
def test_raise_invalid_asset_type_id(invalid_id: str) -> None:
    """Raise exception if the provided asset id contains invalid characters."""
    with pytest.raises(ValueError) as excinfo:
        Asset(asset_id="98765", asset_type_id=invalid_id)
    assert (
        str(excinfo.value)
        == f"invalid identifier '{invalid_id}' - valid characters are [a-zA-Z0-9._\\-+]"
    )


@pytest.mark.parametrize("invalid_id", [("id-€"), ("%-id"), ("id-/")])
def test_raise_invalid_asset_id(invalid_id: str) -> None:
    """Raise exception if the provided id contains invalid characters."""
    with pytest.raises(ValueError) as excinfo:
        Asset(asset_id=invalid_id, asset_type_id="123456")
    assert (
        str(excinfo.value)
        == f"invalid identifier '{invalid_id}' - valid characters are [a-zA-Z0-9._\\-+]"
    )


@pytest.mark.parametrize(
    "invalid_quantity", ["invalid", "", -100, -0.00001, "-0.00001"]
)
def test_raises_invalid_quantity(
    invalid_quantity: typing.Union[str, int, float]
) -> None:
    """Request content to create claims on an unique asset."""
    with pytest.raises(ValueError) as excinfo:
        Asset(asset_type_id="123456", quantity=invalid_quantity),  # type: ignore[arg-type]
    assert (
        str(excinfo.value) == f"must be a whole, positive number: '{invalid_quantity}'"
    )


def test_content_create_asset_request() -> None:
    """Request content to create an account."""
    request_id = "123456"
    asset = Asset(asset_type_id="123456")

    content = json.loads(asset.put_request_content(request_id=request_id))
    assert content == {
        "_type": "CreateAssetRequest",
        "assetId": asset.asset_id,
        "assetTypeId": asset.asset_type_id,
        "requestId": request_id,
    }


@pytest.mark.parametrize("quantity", [0, 100, "0", "300", 0.0, "30.0"])
def test_content_create_account(quantity: typing.Union[str, int, float]) -> None:
    """Request content to create an account."""
    request_id = "123456"
    asset = Asset(asset_type_id="123456", quantity=quantity)  # type: ignore[arg-type]

    content = json.loads(asset.put_request_content(request_id=request_id))
    assert content == {
        "_type": "CreateAssetRequest",
        "assetId": asset.asset_id,
        "assetTypeId": asset.asset_type_id,
        "quantity": str(int(float(quantity))),
        "requestId": request_id,
    }


def test_content_create_asset_claims_request() -> None:
    """Request content to create claims on an unique asset."""
    request_id = "123456"
    claims = [b"claim-1", b"claim-2"]
    asset = Asset(asset_type_id="123456")

    content = json.loads(
        asset.put_request_content(claims=claims, request_id=request_id)
    )
    hashed_claims = content.pop("claims")
    assert content == {
        "_type": "CreateAssetClaimsRequest",
        "subjectId": asset.asset_id,
        "subjectTypeId": asset.asset_type_id,
        "requestId": request_id,
    }
    assert len(hashed_claims) == len(claims)
    for hc in [hashed_claim(c) for c in claims]:
        assert hc in hashed_claims


def test_content_create_endorsements(identity: Identity) -> None:
    """Request content to create claims and endorsements for an unique asset."""
    request_id = "123456"
    claims = [b"claim-1", b"claim-2"]
    asset = Asset(asset_type_id="98765")
    content = json.loads(
        asset.put_request_content(
            claims=claims, endorser=identity, request_id=request_id
        )
    )
    endorsements = content.pop("endorsements")
    assert content == {
        "_type": "CreateAssetEndorsementsRequest",
        "subjectId": asset.asset_id,
        "subjectTypeId": asset.asset_type_id,
        "endorserId": identity.identity_id,
        "requestId": request_id,
    }
    for c, s in endorsements.items():
        identity.verify_signature(
            s, ";".join((asset.asset_id, asset.asset_type_id, c)).encode()
        )


def test_content_raises(identity: Identity) -> None:
    """Request content to create claims and endorsements for an unique asset."""
    asset = Asset(asset_type_id="98765")
    with pytest.raises(TypeError) as exeinfo:
        asset.put_request_content(endorser=identity)
    assert (
        str(exeinfo.value)
        == "missing required keyword argument needed for endorsement: 'claims'"
    )


def test_relative_path() -> None:
    """Return relative URL where the asset information can be read."""
    asset = Asset(asset_type_id="123456")
    assert asset.resource == "/".join(
        ("/api/v1/asset-types", asset.asset_type_id, "assets", asset.asset_id)
    )
