"""Run integration tests against a real platform."""
from typing import List

import pytest

from iov42.core import Asset
from iov42.core import AssetType
from iov42.core import Client
from iov42.core import CryptoProtocol
from iov42.core import hashed_claim
from iov42.core import Identity

IOV42_TEST_SERVICE = "https://api.vienna-integration.poc.iov42.net"


@pytest.fixture(scope="session")
def alice() -> Identity:
    """Returns Alice's new identity with which we create stuff."""
    # TODO: identity = Identity(CryptoProtocol.SHA256WithECDSA)
    return Identity(CryptoProtocol.SHA256WithECDSA.generate_private_key())


@pytest.fixture(scope="session")
def client(alice: Identity) -> Client:
    """Creates identity on an iov42 platform."""
    client = Client(IOV42_TEST_SERVICE, alice)
    client.put(alice)
    return client


@pytest.fixture(scope="session")
def existing_identity_claims(client: Client) -> List[bytes]:
    """Return a list of existing claims against the identity used in the client."""
    claims = [b"alice-claim-1", b"alice-claim-2"]
    client.put(client.identity, claims=claims)
    return claims


@pytest.fixture(scope="session")
def existing_asset_type_id(client: Client) -> str:
    """Creates an asset type on an iov42 platform ."""
    asset_type = AssetType()
    client.put(asset_type)
    return asset_type.asset_type_id


@pytest.fixture(scope="session")
def existing_quantifiable_asset_type_id(client: Client) -> str:
    """Creates a quantifiable asset type on an iov42 platform ."""
    asset_type = AssetType(scale=2)
    client.put(asset_type)
    return asset_type.asset_type_id


@pytest.fixture(scope="session")
def existing_asset(client: Client, existing_asset_type_id: str) -> Asset:
    """Creates an asset on an iov42 platform ."""
    asset = Asset(asset_type_id=existing_asset_type_id)
    client.put(asset)
    return asset


@pytest.fixture(scope="session")
def existing_asset_claims(client: Client, existing_asset: Asset) -> List[bytes]:
    """Return a list of claims endorsed against an asset."""
    claims = [b"asset-claim-1", b"asset-claim-2"]
    client.put(existing_asset, claims=claims, endorse=True, create_claims=True)
    return claims


@pytest.fixture(scope="session")
def bob() -> Identity:
    """Returns Bob's identity used to endorse claims on Alice or her assets."""
    endorser = Identity(CryptoProtocol.SHA256WithECDSA.generate_private_key())
    client = Client(IOV42_TEST_SERVICE, endorser)
    client.put(endorser)
    return endorser


@pytest.mark.integr
def test_create_identity_claims(client: Client) -> None:
    """Alice creates claims against herself."""
    claims = [b"alice-claim-3", b"alice-claim-4"]

    response = client.put(client.identity, claims=claims)

    prefix = "/".join(
        (
            "/api/v1/identities",
            client.identity.identity_id,
            "claims",
        )
    )
    assert len(response.resources) == len(claims)  # type: ignore[union-attr]
    for c in [hashed_claim(c) for c in claims]:
        assert "/".join((prefix, c)) in response.resources  # type: ignore[union-attr]


@pytest.mark.integr
def test_create_identity_claims_with_endorsement(client: Client) -> None:
    """Create endorsements including claims against its own identity."""
    claims = [b"claim-3", b"claim-4"]

    response = client.put(
        client.identity, claims=claims, endorse=True, create_claims=True
    )

    prefix = "/".join(
        (
            "/api/v1/identities",
            client.identity.identity_id,
            "claims",
        )
    )
    # Affected resources: for each endorsements we also created the claim.
    assert len(response.resources) == 2 * len(claims)  # type: ignore[union-attr]
    for c in [hashed_claim(c) for c in claims]:
        assert "/".join((prefix, c)) in response.resources  # type: ignore[union-attr]
        assert (
            "/".join((prefix, c, "endorsements", client.identity.identity_id))
            in response.resources  # type: ignore[union-attr]
        )


@pytest.mark.integr
@pytest.mark.parametrize("asset_type", [AssetType(), AssetType(scale=3)])
def test_create_asset_type(client: Client, asset_type: AssetType) -> None:
    """Create an asset types on an iov42 platform."""
    response = client.put(asset_type)

    assert (
        "/".join(("/api/v1/asset-types", asset_type.asset_type_id))
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
    for c in [hashed_claim(c) for c in claims]:
        assert "/".join((prefix, c)) in response.resources  # type: ignore[union-attr]


@pytest.mark.integr
def test_create_asset_type_claims_with_endorsement(
    client: Client, existing_asset_type_id: str
) -> None:
    """Create asset type claims and endorsements on an unique asset all at once."""
    claims = [b"claim-1", b"claim-2"]

    response = client.put(
        AssetType(existing_asset_type_id),
        claims=claims,
        endorse=True,
        create_claims=True,
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
    for c in [hashed_claim(c) for c in claims]:
        assert "/".join((prefix, c)) in response.resources  # type: ignore[union-attr]
        assert (
            "/".join((prefix, c, "endorsements", client.identity.identity_id))
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
def test_create_account(
    client: Client, existing_quantifiable_asset_type_id: str
) -> None:
    """Create an account on an iov42 platform."""
    account = Asset(asset_type_id=existing_quantifiable_asset_type_id, quantity=0)  # type: ignore[arg-type]

    response = client.put(account)

    assert (
        "/".join(
            ("/api/v1/asset-types", account.asset_type_id, "assets", account.asset_id)
        )
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
    for c in [hashed_claim(c) for c in claims]:
        assert "/".join((prefix, c)) in response.resources  # type: ignore[union-attr]


@pytest.mark.integr
def test_create_asset_claims_with_endorsement(
    client: Client, existing_asset: Asset
) -> None:
    """Create asset claims and (self-) endorsements on an unique asset all at once."""
    claims = [b"claim-1", b"claim-2"]

    response = client.put(
        existing_asset, claims=claims, endorse=True, create_claims=True
    )

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
    for c in [hashed_claim(c) for c in claims]:
        assert "/".join((prefix, c)) in response.resources  # type: ignore[union-attr]
        assert (
            "/".join((prefix, c, "endorsements", client.identity.identity_id))
            in response.resources  # type: ignore[union-attr]
        )


@pytest.mark.integr
def test_read_endorsement_unique_asset(
    client: Client,
    existing_asset: Asset,
    existing_asset_claims: List[bytes],
) -> None:
    """Show how to read an endorsement against an asset claim."""
    response = client.get(
        existing_asset,
        claim=existing_asset_claims[0],
        endorser_id=client.identity.identity_id,
    )
    # What should we return here?
    assert response.proof.startswith("/api/v1/proofs/")
    assert response.endorser_id == client.identity.identity_id  # type: ignore[union-attr]
    assert response.endorsement  # type: ignore[union-attr]


@pytest.mark.integr
def test_3rd_party_endorsements(
    bob: Identity,
    existing_asset: Asset,
    existing_asset_claims: List[bytes],
) -> None:
    """Create 3rd party endorsements against existing claims on an unique asset."""
    bob_client = Client(IOV42_TEST_SERVICE, bob)

    # NOTE: endorser and owner are different, claims already exists
    response = bob_client.put(
        existing_asset, claims=existing_asset_claims, endorse=True
    )

    for r in response.resources:  # type: ignore[union-attr]
        if "endorsements/" in r:
            assert "endorsements/" + bob.identity_id in r


@pytest.mark.integr
def test_3rd_party_endorsements_on_new_claims(
    client: Client,
    existing_asset: Asset,
    bob: Identity,
) -> None:
    """Provide endorsements on someone elses claims which do not exist yet."""
    new_claims = [b"alice-claim-100", b"alice-claims-200"]
    content, authorisation = bob.endorse(existing_asset, new_claims)

    # Content and authorisation has to be handed over from the endorser to the
    # identity owning the asset. The asset owner creates the request to add the
    # claims with endorsements which implicitely adds also the owner's authorisation.
    response = client.put(
        existing_asset,
        claims=new_claims,
        content=content,
        authorisations=[authorisation],
        create_claims=True,
    )

    for r in response.resources:  # type: ignore[union-attr]
        if "endorsements/" in r:
            assert bob.identity_id in r
