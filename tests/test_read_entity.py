"""Test cases for reading entity information."""
import json

import pytest
import respx

from iov42.core import Asset
from iov42.core import Client
from iov42.core import Identity
from iov42.core import InvalidSignature
from iov42.core._crypto import iov42_decode


def test_get_node_id(
    client: Client,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """Retrieve node_id on the very first GET request."""
    client.get(
        Asset(asset_type_id="1234567"),
        claim=b"claim-1",
        endorser_id=client.identity.identity_id,
    )

    assert client.node_id == "node-1"
    assert mocked_requests_200["read_node_info"].call_count == 1


def test_node_id_cached(
    client: Client,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """node_id is cached after the first GET request."""
    client.get(
        Asset(asset_type_id="1234567"),
        claim=b"claim-1",
        endorser_id=client.identity.identity_id,
    )
    client.get(
        Asset(asset_type_id="1234567"),
        claim=b"claim-1",
        endorser_id=client.identity.identity_id,
    )

    assert mocked_requests_200["read_node_info"].call_count == 1


def test_read_unique_asset_endorsement_header(
    client: Client,
    endorser: Identity,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """GET request has only x-iov42-authentication header."""
    asset = Asset(asset_type_id="1234567")
    client.get(asset, claim=b"claim-1", endorser_id=endorser.identity_id)

    assert mocked_requests_200["read_asset_endorsement"].call_count == 1
    http_request, _ = mocked_requests_200["read_asset_endorsement"].calls[0]
    assert [*http_request.headers] == [
        "host",
        "x-iov42-authentication",
    ]


def test_authentication_header(
    client: Client,
    endorser: Identity,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """The x-iov42-authentication header is signed by the identity."""
    asset = Asset(asset_type_id="1234567")
    client.get(asset, claim=b"claim-1", endorser_id=endorser.identity_id)

    http_request, _ = mocked_requests_200["read_asset_endorsement"].calls[0]
    authentication = json.loads(
        iov42_decode(http_request.headers["x-iov42-authentication"].encode())
    )
    assert len(authentication) == 3
    assert authentication["identityId"] == client.identity.identity_id
    assert authentication["protocolId"] == client.identity.private_key.protocol.name


def test_authentication_header_signature(
    client: Client,
    endorser: Identity,
    mocked_requests_200: respx.MockTransport,
) -> None:
    """Signature of x-iov42-authentication header is the signed request URL."""
    asset = Asset(asset_type_id="1234567")
    client.get(asset, claim=b"claim-1", endorser_id=endorser.identity_id)

    http_request, _ = mocked_requests_200["read_asset_endorsement"].calls[0]
    authentication = json.loads(
        iov42_decode(http_request.headers["x-iov42-authentication"].encode())
    )
    try:
        content = http_request.url.raw_path
        client.identity.verify_signature(authentication["signature"], content)
    except InvalidSignature:
        pytest.fail("Signature verification failed")
