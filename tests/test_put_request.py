"""Test cases for creating PUT requests."""
import json
import uuid

import pytest

from iov42.core import Asset
from iov42.core import AssetType
from iov42.core import CryptoProtocol
from iov42.core import Entity
from iov42.core import PrivateIdentity
from iov42.core import Request

entities = [
    PrivateIdentity(
        CryptoProtocol.SHA256WithECDSA.generate_private_key()
    ).public_identity,
    AssetType(),
    Asset(asset_type_id="123456"),
]


def id_class_name(value: Entity) -> str:
    """Provide class name as test identifier."""
    return str(value.__class__.__name__)


@pytest.mark.parametrize("entity", entities, ids=id_class_name)
def test_request_with_id(entity: Entity) -> None:
    """Request with request_id."""
    request = Request("PUT", "https://example.org", entity, request_id="123456")
    assert request.resource == "/api/v1/requests/123456"
    assert request.url == "https://example.org/api/v1/requests/123456"


@pytest.mark.parametrize("entity", entities, ids=id_class_name)
def test_request_url_with_path(entity: Entity) -> None:
    """Request with URL having a path."""
    request = Request("PUT", "https://example.org/test", entity, request_id="98765")
    assert request.resource == "/api/v1/requests/98765"
    assert request.url == "https://example.org/test/api/v1/requests/98765"


@pytest.mark.parametrize("entity", entities, ids=id_class_name)
def test_generated_request_id(entity: Entity) -> None:
    """Generated request is a UUID."""
    request = Request("PUT", "https://example.org", entity)
    assert uuid.UUID(request.url.rsplit("/", 1)[1])


@pytest.mark.parametrize("entity", entities, ids=id_class_name)
def test_no_xiov42_headers(entity: Entity) -> None:
    """PUT request does not contain any x-iov42 headers before authentication."""
    request = Request("PUT", "https://example.org", entity)
    assert [*request.headers] == ["content-type"]
    assert request.authorisations == []


@pytest.mark.parametrize("entity", entities, ids=id_class_name)
def test_add_iov42_headers(identity: PrivateIdentity, entity: Entity) -> None:
    """Authentication adds neccessary x-iov42 headers signed by the identity."""
    request = Request("PUT", "https://example.org", entity)
    request.add_authentication_header(identity)
    assert [*request.headers] == [
        "content-type",
        "x-iov42-authorisations",
        "x-iov42-authentication",
    ]


@pytest.mark.parametrize("entity", entities, ids=id_class_name)
def test_authorised_by(identity: PrivateIdentity, entity: Entity) -> None:
    """Authorization is provided by the correct identity."""
    request = Request("PUT", "https://example.org", entity)
    request.add_authentication_header(identity)

    assert len(request.authorisations) == 1
    assert request.authorisations[0]["identityId"] == identity.identity_id
    assert request.authorisations[0]["protocolId"] == identity.private_key.protocol.name


@pytest.mark.parametrize("entity", entities, ids=id_class_name)
def test_authorised_by_delegate(delegate: PrivateIdentity, entity: Entity) -> None:
    """Authorization is provided by the delegate."""
    request = Request("PUT", "https://example.org", entity)

    # identity.delegate_identity_id = "abcdefgh"
    request.add_authentication_header(delegate)

    assert len(request.authorisations) == 1
    assert request.authorisations[0]["identityId"] == delegate.identity_id
    assert request.authorisations[0]["protocolId"] == delegate.private_key.protocol.name
    assert (
        request.authorisations[0]["delegateIdentityId"] == delegate.delegate_identity_id
    )


@pytest.mark.parametrize("entity", entities, ids=id_class_name)
def test_authorised_by_idempotent(identity: PrivateIdentity, entity: Entity) -> None:
    """Adding authentication is idempotent."""
    request = Request("PUT", "https://example.org", entity)
    request.add_authentication_header(identity)
    request.add_authentication_header(identity)
    assert len(request.authorisations) == 1


@pytest.mark.parametrize(
    "entity,expected_type",
    [
        (
            PrivateIdentity(
                CryptoProtocol.SHA256WithECDSA.generate_private_key()
            ).public_identity,
            "IssueIdentityRequest",
        ),
        (AssetType(), "DefineAssetTypeRequest"),
        (AssetType(scale=2), "DefineAssetTypeRequest"),
        (Asset(asset_type_id="123456"), "CreateAssetRequest"),
        (Asset(asset_type_id="123456", quantity=0), "CreateAssetRequest"),  # type: ignore[arg-type]
        (Asset(asset_type_id="123456", quantity=100), "CreateAssetRequest"),  # type: ignore[arg-type]
        (Asset(asset_type_id="123456", quantity="100"), "CreateAssetRequest"),
        (Asset(asset_type_id="123456", quantity=30.0), "CreateAssetRequest"),  # type: ignore[arg-type]
        (Asset(asset_type_id="123456", quantity="30.0"), "CreateAssetRequest"),
    ],
    ids=id_class_name,
)
def test_create_entity_request(entity: Entity, expected_type: str) -> None:
    """Request type to issue an identity."""
    request = Request("PUT", "https://example.org", entity)

    content = json.loads(request.content)
    assert content["_type"] == expected_type


@pytest.mark.parametrize(
    "subject,expected_type",
    list(
        zip(
            entities + [AssetType(scale=2)],
            [
                "CreateIdentityClaimsRequest",
                "CreateAssetTypeClaimsRequest",
                "CreateAssetClaimsRequest",
                "CreateAssetTypeClaimsRequest",
            ],
        )
    ),
    # TODO: can we create claims against accounts?
    ids=id_class_name,
)
def test_create_identity_claim_request(
    identity: PrivateIdentity, subject: Entity, expected_type: str
) -> None:
    """Request type to create claims against a subject."""
    request = Request(
        "PUT", "https://example.org", subject, claims=[b"claim-1", b"claim-2"]
    )

    content = json.loads(request.content)
    assert content["_type"] == expected_type


@pytest.mark.parametrize("subject", entities, ids=id_class_name)
def test_xiov42_claims_header(subject: Entity) -> None:
    """PUT request to create claims contains x-iov42-claims header."""
    request = Request("PUT", "https://example.org", subject, claims=[b"claim-1"])
    assert [*request.headers] == ["content-type", "x-iov42-claims"]
    assert request.authorisations == []


@pytest.mark.parametrize(
    "subject,expected_type",
    list(
        zip(
            entities,
            [
                "CreateIdentityEndorsementsRequest",
                "CreateAssetTypeEndorsementsRequest",
                "CreateAssetEndorsementsRequest",
            ],
        )
    ),
    ids=id_class_name,
)
def test_create_entity_endorsements_request(
    identity: PrivateIdentity, subject: Entity, expected_type: str
) -> None:
    """Request type to create endorsements against different subject types."""
    request = Request(
        "PUT",
        "https://example.org",
        subject,
        claims=[b"claim-1", b"claim-2"],
        endorser=identity,
    )
    content = json.loads(request.content)
    assert content["_type"] == expected_type


@pytest.mark.parametrize("subject", entities, ids=id_class_name)
def test_raises_claims_missing(identity: PrivateIdentity, subject: Entity) -> None:
    """Raise TyepError if no claims are provided for endorsement."""
    with pytest.raises(TypeError) as excinfo:
        Request(
            "PUT",
            "https://example.org",
            subject,
            endorser=identity,
        )
    assert (
        str(excinfo.value)
        == "missing required keyword argument needed for endorsement: 'claims'"
    )


def test_unknown_method(identity: PrivateIdentity) -> None:
    """We create the request even if the method is bogus."""
    request = Request(
        "FOO",
        "https://example.org",
        Asset(asset_type_id="123456"),
    )
    request.add_authentication_header(identity)
    assert [*request.headers] == []
    assert request.url == "https://example.org"
    assert request.content == b""
    assert not hasattr(request, "resource")
