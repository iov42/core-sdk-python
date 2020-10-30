"""Test cases for GET requests."""
import re
import typing

import pytest

from iov42.core import Asset
from iov42.core import AssetType
from iov42.core import CryptoProtocol
from iov42.core import Entity
from iov42.core import Identity
from iov42.core import Request

entities = [
    (Identity(CryptoProtocol.SHA256WithECDSA.generate_private_key())),
    (AssetType()),
    (Asset(asset_type_id="123456")),
]


def id_class_name(value: Entity) -> str:
    """Provide class name as test identifier."""
    return str(value.__class__.__name__)


@pytest.mark.parametrize("entity", entities, ids=id_class_name)
@pytest.mark.parametrize(
    "claims, endorser_id",
    [(None, None), ([b"claim-1"], None), ([b"claim-1"], "987654")],
)
def test_query_parameters(
    entity: Entity,
    claims: typing.Optional[typing.List[bytes]],
    endorser_id: typing.Optional[str],
) -> None:
    """GET requests has request_id and node_id as query parameters."""
    request = Request(
        "GET",
        "https://example.org/",
        entity,
        claims=claims,
        endorser=endorser_id,
        request_id="123456",
        node_id="node-1",
    )
    assert request.url.rsplit("?")[1] == "requestId=123456&nodeId=node-1"


@pytest.mark.parametrize("entity", entities, ids=id_class_name)
@pytest.mark.parametrize(
    "claims, endorser_id",
    [(None, None), ([b"claim-1"], None), ([b"claim-1"], "987654")],
)
def test_no_xiov42_headers(
    entity: Entity,
    claims: typing.Optional[typing.List[bytes]],
    endorser_id: typing.Optional[str],
) -> None:
    """Non-authenticated GET request has no headers."""
    request = Request(
        "GET",
        "https://example.org/",
        entity,
        claims=claims,
        endorser=endorser_id,
        node_id="node-1",
    )
    assert [*request.headers] == []


@pytest.mark.parametrize("entity", entities, ids=id_class_name)
@pytest.mark.parametrize(
    "claims, endorser_id",
    [(None, None), ([b"claim-1"], None), ([b"claim-1"], "987654")],
)
def test_add_xiov42_headers(
    identity: Identity,
    entity: Entity,
    claims: typing.Optional[typing.List[bytes]],
    endorser_id: typing.Optional[str],
) -> None:
    """Authenticated GET request has only authentication headers."""
    request = Request(
        "GET",
        "https://example.org/",
        entity,
        claims=claims,
        endorser=endorser_id,
        node_id="node-1",
    )
    request.add_authentication_header(identity)
    assert [*request.headers] == ["x-iov42-authentication"]


@pytest.mark.parametrize(
    "url", ["https://example.org", "https://example.org/", "https://example.org/test"]
)
@pytest.mark.parametrize(
    "entity, expected_resource",
    list(
        zip(
            entities,
            [
                "/api/v1/identities/[\\w-]*",
                "/api/v1/asset-types/[\\w-]*",
                "/api/v1/asset-types/[\\w-]*/assets/[\\w-]*",
            ],
        )
    ),
    ids=id_class_name,
)
def test_read_entity(url: str, entity: Entity, expected_resource: str) -> None:
    """URL and resource for GET request are as expected."""
    expected_url = url.rstrip("/") + expected_resource + "\\?"

    request = Request("GET", url, entity, node_id="node-1")

    assert re.search(expected_resource, request.resource)
    assert re.search(expected_url, request.url)


@pytest.mark.parametrize(
    "url", ["https://example.org", "https://example.org/", "https://example.org/test"]
)
@pytest.mark.parametrize(
    "entity, expected_resource",
    list(
        zip(
            entities,
            [
                "/api/v1/identities/[\\w-]*/claims/\\w*",
                "/api/v1/asset-types/[\\w-]*/claims/\\w*",
                "/api/v1/asset-types/[\\w-]*/assets/[\\w-]*/claims/\\w*",
            ],
        )
    ),
    ids=id_class_name,
)
def test_read_claims(url: str, entity: Entity, expected_resource: str) -> None:
    """URL and resource for reading a claim are as expected."""
    expected_url = url.rstrip("/") + expected_resource + "\\?"

    request = Request("GET", url, entity, claims=[b"claim-1"], node_id="node-1")

    assert re.search(expected_resource, request.resource)
    assert re.search(expected_url, request.url)


@pytest.mark.parametrize(
    "url", ["https://example.org", "https://example.org/", "https://example.org/test"]
)
@pytest.mark.parametrize(
    "entity, expected_resource",
    list(
        zip(
            entities,
            [
                "/api/v1/identities/[\\w-]*/claims/\\w*/endorsements/987654",
                "/api/v1/asset-types/[\\w-]*/claims/\\w*/endorsements/987654",
                "/api/v1/asset-types/[\\w-]*/assets/[\\w-]*/claims/\\w*/endorsements/987654",
            ],
        )
    ),
    ids=id_class_name,
)
def test_read_endorsement(url: str, entity: Entity, expected_resource: str) -> None:
    """URL and resource for reading a claim are as expected."""
    expected_url = url.rstrip("/") + expected_resource + "\\?"
    endorser_id = "987654"

    request = Request(
        "GET",
        url,
        entity,
        claims=[b"claim-1"],
        endorser=endorser_id,
        node_id="node-1",
    )

    assert re.search(expected_resource, request.resource)
    assert re.search(expected_url, request.url)


@pytest.mark.skip(reason="not implemented yet")
def test_read_public_key() -> None:
    """Request to read the public key of an identity."""
    pass


@pytest.mark.skip(reason="not implemented yet")
def test_read_delegates_of_identity() -> None:
    """Request to read all delgates of an identity."""
    pass


def test_read_no_node_id() -> None:
    """Raise TypeError if no node_id is provided for a GET request."""
    with pytest.raises(TypeError) as excinfo:
        Request("GET", "https://example.org/", AssetType())
    assert str(excinfo.value) == "missing required keyword argument: 'node_id'"
