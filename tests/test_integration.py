"""Run integration tests against a real platform."""
import pytest

from iov42.core import Asset
from iov42.core import AssetType
from iov42.core import Client
from iov42.core import CryptoProtocol
from iov42.core import Identity
from iov42.core._entity import Claim


@pytest.fixture(scope="session")
def client() -> Client:
    """Creates identity on developer platform ."""
    # TODO: identity = Identity(CryptoProtocol.SHA256WithECDSA)
    identity = Identity(CryptoProtocol.SHA256WithECDSA.generate_private_key())
    # TODO: provide means to change the URL from outside
    client = Client("https://api.sandbox.iov42.dev", identity)
    client.put(identity)
    return client


@pytest.mark.slow
def test_create_asset_type(client: Client) -> None:
    """Create asset type."""
    entity = AssetType()
    response = client.put(entity)
    assert "/".join(("/api/v1/asset-types", entity.id)) == response.resources[0]


@pytest.mark.slow
def test_create_asset(client: Client) -> None:
    """Create asset."""
    asset_type = AssetType()
    client.put(asset_type)
    entity = Asset(asset_type)
    response = client.put(entity)
    assert (
        "/".join(("/api/v1/asset-types", asset_type.id, "assets", entity.id))
        == response.resources[0]
    )


@pytest.mark.slow
def test_create_asset_claims_with_endorsement(client: Client) -> None:
    """Create asset."""
    asset_type = AssetType()
    client.put(asset_type)

    asset = Asset(asset_type)
    client.put(asset)

    prefix = "/".join(
        ("/api/v1/asset-types", asset_type.id, "assets", asset.id, "claims")
    )
    claims = [b"claim-1", b"claim-2"]

    response = client.put(asset, claims=claims, endorse=True)

    # Affected resources: for each endorsements we also created the claim.
    for c in [Claim(c) for c in claims]:
        assert "/".join((prefix, c.hash)) in response.resources
        assert (
            "/".join((prefix, c.hash, "endorsements", client.identity.id))
            in response.resources
        )
