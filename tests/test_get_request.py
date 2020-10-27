"""Test cases for GET requests."""
import uuid

import pytest

from iov42.core import Asset
from iov42.core import AssetType
from iov42.core import hashed_claim
from iov42.core import Identity
from iov42.core import Request


def test_get_headers(identity: Identity) -> None:
    """GET request has no headers."""
    request = Request(
        "GET",
        "https://example.org/",
        identity,
        node_id="node-1",
    )
    assert [*request.headers] == []


def test_read_base_url_with_path(identity: Identity) -> None:
    """Resource and base URL wre joined as expected."""
    request = Request(
        "GET",
        "https://example.org/test",
        identity,
        request_id="1234567",
        node_id="node-1",
    )
    assert (
        request.url
        == "https://example.org/test/api/v1/identities/"
        + identity.identity_id
        + "?requestId=1234567&nodeId=node-1"
    )


def test_read_identity(identity: Identity) -> None:
    """Request to read an information about an identity."""
    # No one needs this request. We probably should retrieve the public key when
    # we provide an identity as entity (see test_read_public_key()).
    request = Request(
        "GET",
        "https://example.org/",
        identity,
        request_id="1234567",
        node_id="node-1",
    )
    assert request.resource == "/api/v1/identities/" + identity.identity_id
    assert (
        request.url
        == "https://example.org/api/v1/identities/"
        + identity.identity_id
        + "?requestId=1234567&nodeId=node-1"
    )


@pytest.mark.skip(reason="not implemented yet")
def test_read_public_key() -> None:
    """Request to read the public key of an identity."""
    pass


def test_read_identity_claim(identity: Identity) -> None:
    """Request to read information about an identity claim."""
    request = Request(
        "GET",
        "https://example.org/",
        identity,
        request_id="1234567",
        claims=[b"claim-1"],
        node_id="node-1",
    )
    expected_resource = "/".join(
        (
            "/api/v1/identities",
            identity.identity_id,
            "claims",
            hashed_claim(b"claim-1"),
        )
    )
    assert request.resource == expected_resource
    assert (
        request.url
        == "https://example.org"
        + expected_resource
        + "?requestId=1234567&nodeId=node-1"
    )


def test_read_identity_claim_endorsement(
    identity: Identity, endorser: Identity
) -> None:
    """Request to read information about an endorsement of an identity claim."""
    request = Request(
        "GET",
        "https://example.org/",
        identity,
        request_id="1234567",
        claims=[b"claim-1"],
        endorser=endorser.identity_id,
        node_id="node-1",
    )
    expected_resource = "/".join(
        (
            "/api/v1/identities",
            identity.identity_id,
            "claims",
            hashed_claim(b"claim-1"),
            "endorsements",
            endorser.identity_id,
        )
    )
    assert request.resource == expected_resource
    assert (
        request.url
        == "https://example.org"
        + expected_resource
        + "?requestId=1234567&nodeId=node-1"
    )


@pytest.mark.skip(reason="not implemented yet")
def test_read_delegates_of_identity() -> None:
    """Request to read all delgates of an identity."""
    pass


def test_read_asset_type() -> None:
    """Request to read an asset."""
    asset_type = AssetType()
    request = Request(
        "GET",
        "https://example.org/",
        asset_type,
        request_id="1234567",
        node_id="node-1",
    )
    expected_resource = "/".join(("/api/v1/asset-types", asset_type.asset_type_id))
    assert request.resource == expected_resource
    assert (
        request.url
        == "https://example.org"
        + expected_resource
        + "?requestId=1234567&nodeId=node-1"
    )


def test_read_asset_type_claim() -> None:
    """Request to read an asset type claims."""
    asset_type = AssetType()
    request = Request(
        "GET",
        "https://example.org/",
        asset_type,
        claims=[b"claim-1"],
        request_id="1234567",
        node_id="node-1",
    )
    expected_resource = "/".join(
        (
            "/api/v1/asset-types",
            asset_type.asset_type_id,
            "claims",
            hashed_claim(b"claim-1"),
        )
    )
    assert request.resource == expected_resource
    assert (
        request.url
        == "https://example.org"
        + expected_resource
        + "?requestId=1234567&nodeId=node-1"
    )


def test_read_asset_type_endorsement(endorser: Identity) -> None:
    """Request to read an asset type endorsement."""
    asset_type = AssetType()
    request = Request(
        "GET",
        "https://example.org/",
        asset_type,
        claims=[b"claim-1"],
        endorser=endorser.identity_id,
        request_id="1234567",
        node_id="node-1",
    )
    expected_resource = "/".join(
        (
            "/api/v1/asset-types",
            asset_type.asset_type_id,
            "claims",
            hashed_claim(b"claim-1"),
            "endorsements",
            endorser.identity_id,
        )
    )
    assert request.resource == expected_resource
    assert (
        request.url
        == "https://example.org"
        + expected_resource
        + "?requestId=1234567&nodeId=node-1"
    )


def test_read_asset() -> None:
    """Request to read an asset."""
    asset = Asset(asset_type_id=str(uuid.uuid4()))
    request = Request(
        "GET",
        "https://example.org/",
        asset,
        request_id="1234567",
        node_id="node-1",
    )
    expected_resource = "/".join(
        (
            "/api/v1/asset-types",
            asset.asset_type_id,
            "assets",
            asset.asset_id,
        )
    )
    assert request.resource == expected_resource
    assert (
        request.url
        == "https://example.org"
        + expected_resource
        + "?requestId=1234567&nodeId=node-1"
    )


def test_read_asset_claim() -> None:
    """Request to read an asset claim."""
    asset = Asset(asset_type_id=str(uuid.uuid4()))
    request = Request(
        "GET",
        "https://example.org/",
        asset,
        claims=[b"claim-1"],
        request_id="1234567",
        node_id="node-1",
    )
    expected_resource = "/".join(
        (
            "/api/v1/asset-types",
            asset.asset_type_id,
            "assets",
            asset.asset_id,
            "claims",
            hashed_claim(b"claim-1"),
        )
    )
    assert request.resource == expected_resource
    assert (
        request.url
        == "https://example.org"
        + expected_resource
        + "?requestId=1234567&nodeId=node-1"
    )


def test_read_asset_endorsement(identity: Identity) -> None:
    """Request to read an asset endorsement."""
    asset = Asset(asset_type_id=str(uuid.uuid4()))
    request = Request(
        "GET",
        "https://example.org/",
        asset,
        claims=[b"claim-1"],
        endorser=identity.identity_id,
        request_id="1234567",
        node_id="node-1",
    )
    expected_resource = "/".join(
        (
            "/api/v1/asset-types",
            asset.asset_type_id,
            "assets",
            asset.asset_id,
            "claims",
            hashed_claim(b"claim-1"),
            "endorsements",
            identity.identity_id,
        )
    )
    assert request.resource == expected_resource
    assert (
        request.url
        == "https://example.org"
        + expected_resource
        + "?requestId=1234567&nodeId=node-1"
    )


def test_read_no_node_id() -> None:
    """Raise TypeError if no node_id is provided for a GET request."""
    with pytest.raises(TypeError) as excinfo:
        Request("GET", "https://example.org/", AssetType())
    assert str(excinfo.value) == "missing required keyword argument: 'node_id'"
