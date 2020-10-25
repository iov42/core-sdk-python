"""Test cases to create an identity on the iov42 platform."""
import json
import re

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
from iov42.core._crypto import iov42_decode


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


def test_iov42_headers(
    client: Client, mocked_requests_200: respx.MockTransport
) -> None:
    """Authenticatino and authorisations are created with the request."""
    _ = client.put(Identity)

    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    assert "content-type" in [*http_request.headers]
    assert "x-iov42-authorisations" in [*http_request.headers]
    assert "x-iov42-authentication" in [*http_request.headers]


def test_authorisations_header(
    client: Client, mocked_requests_200: respx.MockTransport
) -> None:
    """Content of x-iov42-authorisations header to create an identiy."""
    _ = client.put(Identity)

    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    authorisations = json.loads(
        iov42_decode(http_request.headers["x-iov42-authorisations"].encode())
    )
    assert len(authorisations) == 1
    assert authorisations[0]["identityId"] == client.identity.id
    assert authorisations[0]["protocolId"] == client.identity.private_key.protocol.name


@pytest.mark.skip(reason="to decide what we do")
def test_different_identity(
    client: Client, mocked_requests_200: respx.MockTransport
) -> None:
    """Create an identity different than the one used in the client."""
    entity = Identity(CryptoProtocol.SHA256WithECDSA.generate_private_key())
    # This will not work since the public key will not match with the signature.
    # Should we raise exception? We will decide with the creation of a delegated
    # identity how we design the API.
    _ = client.put(entity)


def test_authorisations_signature(
    client: Client, mocked_requests_200: respx.MockTransport
) -> None:
    """Verify signature of x-iov42-authorisations header to create an identity."""
    # _ = client.put(Identity, request_id="e9c79db4-2b8b-439f-95f5-7574005458ef")
    _ = client.put(Identity)

    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    authorisations = json.loads(
        iov42_decode(http_request.headers["x-iov42-authorisations"].encode())
    )
    try:
        content = http_request.read().decode()
        client.identity.verify_signature(authorisations[0]["signature"], content)
    except InvalidSignature:
        pytest.fail("Signature verification failed")


def test_authentication_header(
    client: Client, mocked_requests_200: respx.MockTransport
) -> None:
    """If x-iov42-authentication header is signed by the identity."""
    _ = client.put(Identity)

    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    authentication = json.loads(
        iov42_decode(http_request.headers["x-iov42-authentication"].encode())
    )
    assert authentication["identityId"] == client.identity.id
    assert authentication["protocolId"] == client.identity.private_key.protocol.name


def test_create_identity_authentication_header_signature(
    client: Client, mocked_requests_200: respx.MockTransport
) -> None:
    """Verifies signature of x-iov42-authentication header."""
    _ = client.put(Identity)

    http_request, _ = mocked_requests_200["create_entity"].calls[0]
    authorisations_signatures = ";".join(
        [
            s["signature"]
            for s in json.loads(
                iov42_decode(http_request.headers["x-iov42-authorisations"].encode())
            )
        ]
    )
    authentication = json.loads(
        iov42_decode(http_request.headers["x-iov42-authentication"].encode())
    )
    try:
        client.identity.verify_signature(
            authentication["signature"], authorisations_signatures
        )
    except InvalidSignature:
        pytest.fail("Signature verification failed")


# From here on we have the error handling


@respx.mock
@pytest.mark.parametrize(
    "invalid_request_id",
    [("request-€"), ("%-request"), ("request-/")],
)
def test_invalid_request_id(client: Client, invalid_request_id: str) -> None:
    """Raise exception if the provided request ID contains invalid charatcers."""
    with pytest.raises(ValueError) as excinfo:
        client.put(Identity, request_id=invalid_request_id)
    # No request is sent
    assert not respx.calls
    assert (
        str(excinfo.value)
        == f"invalid identifier '{invalid_request_id}' - valid characters are [a-zA-Z0-9._\\-+]"
    )


@pytest.mark.errortest
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
            client.put(Identity, request_id="1234567")
        assert str(excinfo.value) == "request ID already exists"
        assert excinfo.value.request_id == "1234567"


@pytest.mark.errortest
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
            client.put(Identity, request_id="1234567")
        assert str(excinfo.value) == "identity 'test-1234' already exists"
        assert excinfo.value.request_id == "1234567"
        # TODO: provide the proof of the existing asset
        # assert excinfo.value.proof == "2602"
        # assert e_info.errors[0].error_type == "2602"


@pytest.mark.errortest
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
            client.put(Identity, request_id="1234567")
        assert str(excinfo.value) == "identity 'test-1234' already exists"
        assert excinfo.value.request_id == "1234567"
        # TODO: provide the error list


@respx.mock
@pytest.mark.errortest
def test_raise_on_request_error(client: Client) -> None:
    """If raise exception on a request error."""
    respx.put(
        re.compile("https://api.sandbox.iov42.dev/api/v1/requests/.*$"),
        content=httpcore.ConnectError(),
    )

    # TODO: do we really want to leak httpx to our clients?
    # We could catch all exception thrown by httpx, wrap it in a few library
    # exceptions and rethrow those.
    with pytest.raises(httpx.ConnectError):
        client.put(Identity)
