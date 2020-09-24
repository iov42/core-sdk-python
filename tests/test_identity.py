"""Test cases for working with iov42 identities."""
import base64
import json
import re
import uuid
from dataclasses import FrozenInstanceError

import httpcore
import httpx
import pytest
import respx

from iov42.core import AssetAlreadyExists
from iov42.core import Client
from iov42.core import CryptoProtocol
from iov42.core import DuplicateRequestId
from iov42.core import Identity
from iov42.core import InvalidSignature
from iov42.core import PrivateKey


@pytest.fixture
def public_key_rsa_base64() -> str:
    """Public key encoded as provided by the platform."""
    return (
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhHm7QRpjAY0-6G7yVmQ2y3-zf8eV7UY2u22"
        "fT6pvpvalF4dpxbaEq3PNJps6Kx08_uD7hZCflhMfkwiyqiGPvGkGVLa9dPRR1rqAKgyYw3iSQOPR19"
        "F_9PCslwsqSteSGdcDuw35hDZj-TLbUxY3keKZ6bjdQRaKbrjTSaRmA2gVuHqvxuKEyLjEv77vQJ0l4"
        "nZbTe8pNrcg1unUmnuBhyehcxKb1xxPnkhh-E1uhSs8XamXeeMYCdtstOCTp4Rnorogby4GmWjoftUU"
        "ohw5dUKrekTUvuTHCDgFi9jjOyDz-x7YSSVkFyGhwJY0VIPtUaHvRmECk44wOP1D2SyC-QIDAQAB"
    )


def str_decode(data: str) -> str:
    """Standard decoding of strings."""
    return base64.urlsafe_b64decode(data + "==").decode()


def test_identity() -> None:
    """Creates identity with ID."""
    idenity = Identity(CryptoProtocol.SHA256WithRSA.generate_private_key(), "1234567")
    assert idenity.identity_id == "1234567"
    assert isinstance(idenity.private_key, PrivateKey)


def test_identity_raises_typerror() -> None:
    """Raise TypeError in case no private key is ptovided."""
    with pytest.raises(TypeError) as excinfo:
        Identity("123456")  # type: ignore[arg-type]
    assert str(excinfo.value) == "must be PrivateKey, not str"


def test_identity_default_uuid() -> None:
    """Generated ID is an UUID."""
    identity = Identity(CryptoProtocol.SHA256WithECDSA.generate_private_key())
    assert uuid.UUID(identity.identity_id)


@pytest.mark.parametrize(
    "invalid_identity_id",
    [("test-€"), ("%-abcdef"), ("test-/")],
)
def test_invalid_identity_id2(invalid_identity_id: str) -> None:
    """Raises ValueError in case the provided ID is invalid."""
    with pytest.raises(ValueError) as excinfo:
        Identity(
            CryptoProtocol.SHA256WithECDSA.generate_private_key(), invalid_identity_id
        )
    assert (
        str(excinfo.value)
        == f"invalid identifier '{invalid_identity_id}' - valid characters are [a-zA-Z0-9_.-+]"
    )


def test_identity_immutable() -> None:
    """Raises ValueError in case the provided ID is invalid."""
    with pytest.raises(FrozenInstanceError):
        identity = Identity(CryptoProtocol.SHA256WithECDSA.generate_private_key())
        identity.identity_id = "new-id"  # type: ignore[misc]


def test_create_identity_call_endpoint(
    client: Client, mocked_create_identity: respx.MockTransport
) -> None:
    """It sends a HTTP request to create an identity."""
    request_id = "1234567"
    _ = client.create_identity(request_id=request_id)

    assert mocked_create_identity["create_identity"].call_count == 1
    # TODO: check request_id on URL


def test_create_identity_content_type(
    client: Client, mocked_create_identity: respx.MockTransport
) -> None:
    """It sends a request header with the expected content-type."""
    _ = client.create_identity()

    http_request, _ = mocked_create_identity["create_identity"].calls[0]
    assert http_request.headers["content-type"] == "application/json"


def test_create_identity_default_request_id(
    client: Client, mocked_create_identity: respx.MockTransport
) -> None:
    """It generates an UUID for the request ID if the request ID is not provided."""
    _ = client.create_identity()

    http_request, _ = mocked_create_identity["create_identity"].calls[0]
    # We have to call read(), otherwise we get an httpx.RequestNoRead reading
    # the content (see https://github.com/lundberg/respx/issues/83).
    content = json.loads(http_request.read())
    assert uuid.UUID(content["requestId"])


def test_create_identity_content(
    client: Client,
    public_key_rsa_base64: str,
    mocked_create_identity: respx.MockTransport,
) -> None:
    """It sends the request body to create an identity as expected."""
    _ = client.create_identity(
        request_id="e9c79db4-2b8b-439f-95f5-7574005458ef",
    )

    http_request, _ = mocked_create_identity["create_identity"].calls[0]
    # We have to call read(), otherwise we get an httpx.RequestNoRead reading
    # the content (see https://github.com/lundberg/respx/issues/83).
    content = json.loads(http_request.read())
    assert content["_type"] == "IssueIdentityRequest"
    assert content["requestId"] == "e9c79db4-2b8b-439f-95f5-7574005458ef"
    assert content["identityId"] == client.identity.identity_id
    assert (
        content["publicCredentials"]["protocolId"]
        == client.identity.private_key.protocol.name
    )
    assert content["publicCredentials"]["key"] == public_key_rsa_base64


def test_create_identity_authorisations_header(
    client: Client, mocked_create_identity: respx.MockTransport
) -> None:
    """Content of x-iov42-authorisations header to create an identiy."""
    _ = client.create_identity(
        request_id="e9c79db4-2b8b-439f-95f5-7574005458ef",
    )

    http_request, _ = mocked_create_identity["create_identity"].calls[0]
    authorisations = json.loads(
        str_decode(http_request.headers["x-iov42-authorisations"])
    )

    assert len(authorisations) == 1
    assert (
        authorisations[0]["identityId"]
        == "itest-id-0a9ad8d5-cb84-4f3d-ae7b-94687fe4d7a0"
    )
    assert authorisations[0]["protocolId"] == client.identity.private_key.protocol.name


def test_create_identity_authorisations_signature(
    client: Client, mocked_create_identity: respx.MockTransport
) -> None:
    """Verify signature of x-iov42-authorisations header to create an identity."""
    _ = client.create_identity(
        request_id="e9c79db4-2b8b-439f-95f5-7574005458ef",
    )

    http_request, _ = mocked_create_identity["create_identity"].calls[0]
    authorisations = json.loads(
        str_decode(http_request.headers["x-iov42-authorisations"])
    )
    try:
        content = http_request.read().decode()
        # TODO: provide Identity.verify_signature()
        client.identity.private_key.public_key().verify_signature(
            authorisations[0]["signature"], content
        )
    except InvalidSignature:
        pytest.fail("Signature verification failed")


def test_create_identity_authentication_header(
    client: Client, mocked_create_identity: respx.MockTransport
) -> None:
    """If x-iov42-authentication header is signed by the identity."""
    _ = client.create_identity(
        request_id="e9c79db4-2b8b-439f-95f5-7574005458ef",
    )

    http_request, _ = mocked_create_identity["create_identity"].calls[0]
    authentication = json.loads(
        str_decode(http_request.headers["x-iov42-authentication"])
    )

    assert (
        authentication["identityId"] == "itest-id-0a9ad8d5-cb84-4f3d-ae7b-94687fe4d7a0"
    )
    assert authentication["protocolId"] == client.identity.private_key.protocol.name


def test_create_identity_authentication_header_signature(
    client: Client, mocked_create_identity: respx.MockTransport
) -> None:
    """Verifies signature of x-iov42-authentication header."""
    _ = client.create_identity(
        request_id="e9c79db4-2b8b-439f-95f5-7574005458ef",
    )

    http_request, _ = mocked_create_identity["create_identity"].calls[0]
    authorisations_signatures = ";".join(
        [
            s["signature"]
            for s in json.loads(
                str_decode(http_request.headers["x-iov42-authorisations"])
            )
        ]
    )
    authentication = json.loads(
        str_decode(http_request.headers["x-iov42-authentication"])
    )

    try:
        client.identity.private_key.public_key().verify_signature(
            authentication["signature"], authorisations_signatures
        )
    except InvalidSignature:
        pytest.fail("Signature verification failed")


def test_create_identity_response(
    client: Client, mocked_create_identity: respx.MockTransport
) -> None:
    """Content of the platform response to the create identity request."""
    request = client.create_identity(
        request_id="e9c79db4-2b8b-439f-95f5-7574005458ef",
    )

    assert request.request_id == "e9c79db4-2b8b-439f-95f5-7574005458ef"
    assert request.proof == "/api/v1/proofs/e9c79db4-2b8b-439f-95f5-7574005458ef"
    assert request.resources == [
        "/api/v1/identities/itest-id-0a9ad8d5-cb84-4f3d-ae7b-94687fe4d7a0"
    ]


# From here on we have the error handling


@pytest.mark.parametrize(
    "invalid_request_id",
    [("request-€"), ("%-request"), ("request-/")],
)
def test_invalid_request_id(client: Client, invalid_request_id: str) -> None:
    """Raise exception if the provided request ID contains invalid charatcers."""
    with respx.mock(assert_all_called=False) as respx_mock:
        with pytest.raises(ValueError) as excinfo:
            client.create_identity(request_id=invalid_request_id)
        # No request is sent
        assert not respx_mock.stats.called
        assert (
            str(excinfo.value)
            == f"invalid address '{invalid_request_id}' - valid characters are [a-zA-Z0-9_.-+/]"
        )


def test_raise_duplicate_request_id(client: Client) -> None:
    """Raise exception when the request_id already exists."""
    with respx.mock(base_url="https://api.sandbox.iov42.dev") as respx_mock:
        respx_mock.put(
            re.compile("/api/v1/requests/.*$"),
            status_code=409,
            content=(
                '{"errors":[{"errorCode":2701,"errorType":"RequestId",'
                '"message":"Found duplicate request id"}],"requestId":"1234567"}'
            ),
        )
        with pytest.raises(DuplicateRequestId) as excinfo:
            client.create_identity(request_id="1234567")
        assert str(excinfo.value) == "request ID already exists"
        assert excinfo.value.request_id == "1234567"


def test_raise_identity_already_exists(client: Client) -> None:
    """Raise exception when an identity already exists."""
    client.identity = Identity(
        CryptoProtocol.SHA256WithECDSA.generate_private_key(), "test-1234"
    )
    with respx.mock(base_url="https://api.sandbox.iov42.dev") as respx_mock:
        respx_mock.put(
            re.compile("/api/v1/requests/.*$"),
            status_code=400,
            content=(
                '{"errors":[{"errorCode":2602,"errorType":"AssetExistence",'
                '"message":"Another identity with address test-1234 already exists"}],'
                '"requestId":"1234567","proof":"/api/v1/proofs/23343456"}'
            ),
        )
        with pytest.raises(AssetAlreadyExists) as excinfo:
            client.create_identity(request_id="1234567")
        assert str(excinfo.value) == "identity 'test-1234' already exists"
        assert excinfo.value.request_id == "1234567"
        # TODO: provide the proof of the existing asset
        # assert excinfo.value.proof == "2602"
        # assert e_info.errors[0].error_type == "2602"


def test_raise_identity_already_exists_2(client: Client) -> None:
    """Raise exception when an identity (with an other key) already exists."""
    client.identity = Identity(
        CryptoProtocol.SHA256WithECDSA.generate_private_key(), "test-1234"
    )
    with respx.mock(base_url="https://api.sandbox.iov42.dev") as respx_mock:
        respx_mock.put(
            re.compile("/api/v1/requests/.*$"),
            status_code=400,
            content=(
                '{"errors":[{"errorCode":2503,"errorType":"Authorisation",'
                '"message":"Signature L-IjTeba3wvJn4hHR40GPCG-H7iIeDWOzBo3hCK7x1mLZgif'
                "SdgR-YVxOZtvPzHaI86WdhIL3y-sNOwYUf2c0j7OfT31dAX71W9le-Cp2Mx1PgjjqI09f"
                "i0Nku-h5lgipQ07VKAm3gUx0foeG9GdDQe_I85QuCqtJsaAXWDVc8r0NeWpa3dnQEflIm"
                "W0-gecjO6pYDeyXPALcvp9h8Q_TxkuGVvreqpWvgKzdPMlXHMbN3wYoLNNLM3gpqrqAp"
                "Eze1aTqtlK6gCQUuhsJlKe4Bb2Nj8MRxXXXNpxIJqjJHM0IRps5J0U8gsnEEcny8Zf0tB"
                'h7NGkTteNv554QUbNVA cannot be verified with public credentials of identity test-1234."},'
                '{"errorCode":2503,"errorType":"Authorisation","message":"Signature '
                "L2PIREIx1MZsjV-j0fSMoN3u1eHP2wyqUpAs1mOWdp8k8yrnoBTbyH2Uxw8_9zYTzDHrz"
                "rI16fNKeRFuLlHosWqzoUf41M0Nip5zbW6gmPYiL05AWPdH1pg9qS-cgQa9IFXiMUkZh9"
                "EZltT7HHl9aRn35kcwoJYAoPm96Up1YPI0JWISx1iXXEAcxVOA1N_k-l0tT5Tb7lWNOI4"
                "5eh6flW_vVEeBQDjQhkl94rlP3qDFlDYZ9HZS2A3lTkiIo6MsU57pxeTD9FqwZ8uofJ3O"
                "Yx05TJKl106GPsscf2mnpnQGEzgS20QsJyqUs_u7dpZbAcjfBsaHucVz8gwkz_PoNg "
                'cannot be verified with public credentials of identity test-1234."},'
                '{"errorCode":2602,"errorType":"AssetExistence",'
                '"message":"Another identity with address test-1234 already exists"}],'
                '"requestId":"23343439","proof":"/api/v1/proofs/23343439"}'
            ),
        )
        with pytest.raises(AssetAlreadyExists) as excinfo:
            client.create_identity(request_id="1234567")
        assert str(excinfo.value) == "identity 'test-1234' already exists"
        assert excinfo.value.request_id == "1234567"
        # TODO: provide the error list


@respx.mock
def test_create_identity_request_error(client: Client) -> None:
    """If raise exception on a request error."""
    respx.put(
        re.compile("https://api.sandbox.iov42.dev/api/v1/requests/.*$"),
        content=httpcore.ConnectError(),
    )

    # TODO: do we really want to leak httpx to our clients?
    # We could catch all exception thrown by httpx, wrap it in a few library
    # exceptions and rethrow those.
    with pytest.raises(httpx.ConnectError):
        client.create_identity()
