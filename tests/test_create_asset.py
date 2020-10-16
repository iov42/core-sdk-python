"""Tests creation of an asset."""
import json
import uuid

import respx

from iov42.core import Asset
from iov42.core import AssetType
from iov42.core import Client


def test_create_asset_call_endpoint(
    client: Client,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """It sends a HTTP request to create an asset-type."""
    _ = client.create_asset("123456")

    assert mocked_requests_200["create_entity"].call_count == 1


def test_create_asset_content(
    client: Client,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """It sends the request body to create an asset type as expected."""
    _ = client.create_asset(
        "085f2066-d469-4a45-b7d8-b12f145a2e59",
        request_id="96bd237d-9fe1-4a8e-b271-7cf33e6ec5cb",
    )

    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    content = json.loads(http_request.read())
    assert content["_type"] == "CreateAssetRequest"
    assert uuid.UUID(content["assetId"])
    assert content["assetTypeId"] == "085f2066-d469-4a45-b7d8-b12f145a2e59"
    assert content["requestId"] == "96bd237d-9fe1-4a8e-b271-7cf33e6ec5cb"


def test_create_asset_with_asset_type(
    client: Client,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """It sends the request body to create an asset type as expected."""
    _ = client.create_asset(AssetType("085f2066-d469-4a45-b7d8-b12f145a2e59"))

    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    content = json.loads(http_request.read())
    assert uuid.UUID(content["assetId"])
    assert content["assetTypeId"] == "085f2066-d469-4a45-b7d8-b12f145a2e59"


def test_create_asset_with_asset(
    client: Client,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """It sends the request body to create an asset type as expected."""
    asset = Asset(AssetType("085f2066-d469-4a45-b7d8-b12f145a2e59"), "12345")
    _ = client.create_asset(asset)

    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    content = json.loads(http_request.read())
    assert content["assetId"] == asset.id
    assert content["assetTypeId"] == "085f2066-d469-4a45-b7d8-b12f145a2e59"


def test_create_asset_with_str(
    client: Client,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """It sends the request body to create an asset type as expected."""
    _ = client.create_asset("085f2066-d469-4a45-b7d8-b12f145a2e59", asset_id="12345")

    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    content = json.loads(http_request.read())
    assert content["assetId"] == "12345"
    assert content["assetTypeId"] == "085f2066-d469-4a45-b7d8-b12f145a2e59"
