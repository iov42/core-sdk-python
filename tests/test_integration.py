"""Run integration tests against a real platform."""
from typing import List

import pytest

from iov42.core import Asset
from iov42.core import AssetType
from iov42.core import Client
from iov42.core import CryptoProtocol
from iov42.core import Identity
from iov42.core._entity import Claim


@pytest.fixture(scope="session")
def client() -> Client:
    """Creates identity on an iov42 platform ."""
    # TODO: identity = Identity(CryptoProtocol.SHA256WithECDSA)
    identity = Identity(CryptoProtocol.SHA256WithECDSA.generate_private_key())
    # TODO: provide means to set the URL from pytest command line.
    client = Client("https://api.vienna-integration.poc.iov42.net", identity)
    client.put(identity)
    return client


@pytest.fixture(scope="session")
def existing_asset_type_id(client: Client) -> str:
    """Creates an asset type on an iov42 platform ."""
    asset_type = AssetType()
    client.put(asset_type)
    return asset_type.asset_type_id


@pytest.fixture(scope="session")
def existing_asset(client: Client, existing_asset_type_id: str) -> Asset:
    """Creates an asset on an iov42 platform ."""
    asset = Asset(asset_type_id=existing_asset_type_id)
    client.put(asset)
    return asset


# @pytest.fixture(scope="session")
# def endorser() -> Identity:
#     """Returns an identiy used to endorse claims."""
#     endorser = Identity(CryptoProtocol.SHA256WithECDSA.generate_private_key())
#     client = Client("https://api.vienna-integration.poc.iov42.net", endorser)
#     client.put(endorser)
#     return endorser


@pytest.fixture(scope="session")
def self_endorsed_claims(client: Client, existing_asset: Asset) -> List[bytes]:
    """Return a list of claims endorsed on an iov42 platform."""
    claims = [b"claim-1", b"claim-2"]
    client.put(existing_asset, claims=claims, endorse=True)
    return claims


@pytest.mark.integr
def test_create_identity_claims(client: Client) -> None:
    """Create asset claims on an asset type."""
    claims = [b"claim-1", b"claim-2"]

    response = client.put(client.identity, claims=claims)

    prefix = "/".join(
        (
            "/api/v1/identities",
            client.identity.identity_id,
            "claims",
        )
    )
    assert len(response.resources) == len(claims)  # type: ignore[union-attr]
    for c in [Claim(c) for c in claims]:
        assert "/".join((prefix, c.hash)) in response.resources  # type: ignore[union-attr]


@pytest.mark.integr
def test_create_asset_type(client: Client) -> None:
    """Create an unique asset type on an iov42 platform."""
    entity = AssetType()

    response = client.put(entity)

    assert (
        "/".join(("/api/v1/asset-types", entity.asset_type_id))
        == response.resources[0]  # type: ignore[union-attr]
    )


@pytest.mark.integr
def test_create_asset_type_claims(client: Client, existing_asset_type_id: str) -> None:
    """Create asset claims on an asset type."""
    claims = [b"claim-1", b"claim-2"]

    response = client.put(AssetType(existing_asset_type_id), claims=claims)

    prefix = "/".join(
        (
            "/api/v1/asset-types",
            existing_asset_type_id,
            "claims",
        )
    )
    assert len(response.resources) == len(claims)  # type: ignore[union-attr]
    for c in [Claim(c) for c in claims]:
        assert "/".join((prefix, c.hash)) in response.resources  # type: ignore[union-attr]


@pytest.mark.integr
def test_create_asset_type_claims_with_endorsement(
    client: Client, existing_asset_type_id: str
) -> None:
    """Create asset type claims and endorsements on an unique asset all at once."""
    claims = [b"claim-1", b"claim-2"]

    response = client.put(
        AssetType(existing_asset_type_id), claims=claims, endorse=True
    )

    prefix = "/".join(
        (
            "/api/v1/asset-types",
            existing_asset_type_id,
            "claims",
        )
    )
    # Affected resources: for each endorsements we also created the claim.
    assert len(response.resources) == 2 * len(claims)  # type: ignore[union-attr]
    for c in [Claim(c) for c in claims]:
        assert "/".join((prefix, c.hash)) in response.resources  # type: ignore[union-attr]
        assert (
            "/".join((prefix, c.hash, "endorsements", client.identity.identity_id))
            in response.resources  # type: ignore[union-attr]
        )


@pytest.mark.integr
def test_create_asset(client: Client, existing_asset_type_id: str) -> None:
    """Create an unique asset on an iov42 platform."""
    asset = Asset(asset_type_id=existing_asset_type_id)

    response = client.put(asset)

    assert (
        "/".join(("/api/v1/asset-types", asset.asset_type_id, "assets", asset.asset_id))
        == response.resources[0]  # type: ignore[union-attr]
    )


@pytest.mark.integr
def test_create_asset_claims(client: Client, existing_asset: Asset) -> None:
    """Create asset claims on an unique asset."""
    claims = [b"claim-3", b"claim-4"]

    response = client.put(existing_asset, claims=claims)

    prefix = "/".join(
        (
            "/api/v1/asset-types",
            existing_asset.asset_type_id,
            "assets",
            existing_asset.asset_id,
            "claims",
        )
    )
    assert len(response.resources) == len(claims)  # type: ignore[union-attr]
    for c in [Claim(c) for c in claims]:
        assert "/".join((prefix, c.hash)) in response.resources  # type: ignore[union-attr]


@pytest.mark.integr
def test_create_asset_claims_with_endorsement(
    client: Client, existing_asset: Asset
) -> None:
    """Create asset claims and endorsements on an unique asset all at once."""
    claims = [b"claim-1", b"claim-2"]

    response = client.put(existing_asset, claims=claims, endorse=True)

    prefix = "/".join(
        (
            "/api/v1/asset-types",
            existing_asset.asset_type_id,
            "assets",
            existing_asset.asset_id,
            "claims",
        )
    )
    # Affected resources: for each endorsements we also created the claim.
    assert len(response.resources) == 2 * len(claims)  # type: ignore[union-attr]
    for c in [Claim(c) for c in claims]:
        assert "/".join((prefix, c.hash)) in response.resources  # type: ignore[union-attr]
        assert (
            "/".join((prefix, c.hash, "endorsements", client.identity.identity_id))
            in response.resources  # type: ignore[union-attr]
        )


@pytest.mark.integr
def test_read_endorsement_unique_asset(
    client: Client,
    existing_asset: Asset,
    self_endorsed_claims: List[bytes],
) -> None:
    """Show how to read an asset endorsement."""
    response = client.get(
        existing_asset,
        claim=self_endorsed_claims[0],
        endorser_id=client.identity.identity_id,
    )
    # What should we return here?
    assert response.proof.startswith("/api/v1/proofs/")
    assert response.endorser_id == client.identity.identity_id  # type: ignore[union-attr]
    assert response.endorsement  # type: ignore[union-attr]
