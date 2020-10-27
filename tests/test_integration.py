"""Run integration tests against a real platform."""
from typing import List

import pytest

from iov42.core import Asset
from iov42.core import AssetType
from iov42.core import Client
from iov42.core import CryptoProtocol
from iov42.core import hashed_claim
from iov42.core import Identity
from iov42.core import Request

IOV42_TEST_SERVICE = "https://api.vienna-integration.poc.iov42.net"


@pytest.fixture(scope="session")
def client() -> Client:
    """Creates identity on an iov42 platform ."""
    # TODO: identity = Identity(CryptoProtocol.SHA256WithECDSA)
    identity = Identity(CryptoProtocol.SHA256WithECDSA.generate_private_key())
    # TODO: provide means to set the URL from pytest command line.
    client = Client(IOV42_TEST_SERVICE, identity)
    client.put(identity)
    return client


@pytest.fixture(scope="session")
def existing_asset_type_id(client: Client) -> str:
    """Creates an asset type on an iov42 platform ."""
    asset_type = AssetType()
    client.put(asset_type)
    return asset_type.asset_type_id


@pytest.fixture(scope="session")
def existing_quantifiable_asset_type_id(client: Client) -> str:
    """Creates a quantfiable asset type on an iov42 platform ."""
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
def endorser() -> Identity:
    """Returns an identiy used to endorse claims."""
    endorser = Identity(CryptoProtocol.SHA256WithECDSA.generate_private_key())
    client = Client(IOV42_TEST_SERVICE, endorser)
    client.put(endorser)
    return endorser


@pytest.fixture(scope="session")
def existing_claims(client: Client, existing_asset: Asset) -> List[bytes]:
    """Return a list of claims endorsed on an iov42 platform."""
    claims = [b"claim-1", b"claim-2"]
    client.put(existing_asset, claims=claims, endorse=True)
    return claims


@pytest.mark.integr
def test_create_identity_claims(client: Client) -> None:
    """Create asset claims against an identity."""
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
    for c in [hashed_claim(c) for c in claims]:
        assert "/".join((prefix, c)) in response.resources  # type: ignore[union-attr]


@pytest.mark.integr
def test_create_identity_claims_with_endorsement(client: Client) -> None:
    """Create asset type claims and endorsements against an identity all at once."""
    claims = [b"claim-3", b"claim-4"]

    response = client.put(client.identity, claims=claims, endorse=True)

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
def test_create_asset_type(client: Client) -> None:
    """Create an unique asset type on an iov42 platform."""
    entity = AssetType()

    response = client.put(entity)

    assert (
        "/".join(("/api/v1/asset-types", entity.asset_type_id))
        == response.resources[0]  # type: ignore[union-attr]
    )


@pytest.mark.integr
def test_create_quantifiable_asset_type(client: Client) -> None:
    """Create a quantifiable asset type on an iov42 platform."""
    entity = AssetType(scale=3)

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
    for c in [hashed_claim(c) for c in claims]:
        assert "/".join((prefix, c)) in response.resources  # type: ignore[union-attr]


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
    existing_claims: List[bytes],
) -> None:
    """Show how to read an endorsement against an asset claim."""
    response = client.get(
        existing_asset,
        claim=existing_claims[0],
        endorser_id=client.identity.identity_id,
    )
    # What should we return here?
    assert response.proof.startswith("/api/v1/proofs/")
    assert response.endorser_id == client.identity.identity_id  # type: ignore[union-attr]
    assert response.endorsement  # type: ignore[union-attr]


# According to the API documentation the authorisation to the identiy of the
# subject does not need to authorise the request since the claim already exists.
# But we still get error 2501 "Missing authorisation from identity".
@pytest.mark.integr
@pytest.mark.skip(reason="Missing authorisation from identity")
def test_create_asset_claim_endorsements(
    endorser: Identity,
    existing_asset: Asset,
    existing_claims: List[bytes],
) -> None:
    """Create 3rd party endorsements against existing claims on an unique asset."""
    client = Client(IOV42_TEST_SERVICE, endorser)

    # NOTE: the endorser identity is used to sign this endorsement
    response = client.put(existing_asset, claims=existing_claims, endorse=True)

    for r in response.resources:  # type: ignore[union-attr]
        assert "endorsements/" + endorser.identity_id in r


@pytest.mark.integr
def test_endorse_claims(
    client: Client,
    existing_asset: Asset,
    existing_claims: List[bytes],
    endorser: Identity,
) -> None:
    """Endorse someone elses claims."""
    content = existing_asset.put_request_content(
        claims=existing_claims, endorser=endorser
    )
    authorisation = Request.create_signature(endorser, content)

    # Content and authorisation has to be handed over from the endorser to the
    # identity owning the asset. The asset owner creates the request to add the
    # endorsements which adds his authorisation.
    response = client.put(
        existing_asset,
        claims=existing_claims,
        content=content,
        authorisations=[authorisation],
    )

    for r in response.resources:  # type: ignore[union-attr]
        if "endorsements/" in r:
            assert endorser.identity_id in r
