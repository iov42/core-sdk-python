"""Test cases with focus on errors reported by the iov42 platform."""
import re

import httpcore
import httpx
import pytest
import respx
import tests.config as cfg

from iov42.core import Client
from iov42.core import CryptoProtocol
from iov42.core import DuplicateRequestId
from iov42.core import EntityAlreadyExists
from iov42.core import PrivateIdentity

PLATFORM_URL = cfg.tests["platform_url"]


@pytest.mark.skip(reason="error handling not implemented")
@pytest.mark.errortest
def test_raise_duplicate_request_id(client: Client) -> None:
    """Raise exception when the request_id already exists."""
    with respx.mock(base_url=PLATFORM_URL) as respx_mock:
        respx_mock.put(
            re.compile("/api/v1/requests/.*$"),
            status_code=409,
            content=(
                '{"errors":[{"errorCode":2701,"errorType":"RequestId",'
                '"message":"Found duplicate request id"}],"requestId":"1234567"}'
            ),
        )
        with pytest.raises(DuplicateRequestId) as excinfo:
            client.put(client.identity.public_identity, request_id="1234567")
        assert str(excinfo.value) == "request ID already exists"
        assert excinfo.value.request_id == "1234567"


@pytest.mark.skip(reason="error handling not implemented")
@pytest.mark.errortest
def test_raise_identity_already_exists(client: Client) -> None:
    """Raise exception when an identity already exists."""
    client.identity = PrivateIdentity(
        CryptoProtocol.SHA256WithECDSA.generate_private_key(), "test-1234"
    )
    with respx.mock(base_url=PLATFORM_URL) as respx_mock:
        respx_mock.put(
            re.compile("/api/v1/requests/.*$"),
            status_code=400,
            content=(
                '{"errors":[{"errorCode":2602,"errorType":"AssetExistence",'
                '"message":"Another identity with address test-1234 already exists"}],'
                '"requestId":"1234567","proof":"/api/v1/proofs/23343456"}'
            ),
        )
        with pytest.raises(EntityAlreadyExists) as excinfo:
            client.put(client.identity.public_identity, request_id="1234567")
        assert str(excinfo.value) == "identity 'test-1234' already exists"
        assert excinfo.value.request_id == "1234567"
        # TODO: provide the proof of the existing asset
        # assert excinfo.value.proof == "2602"
        # assert e_info.errors[0].error_type == "2602"


@pytest.mark.skip(reason="error handling not implemented")
@pytest.mark.errortest
def test_raise_identity_already_exists_2(client: Client) -> None:
    """Raise exception when an identity (with an other key) already exists."""
    client.identity = PrivateIdentity(
        CryptoProtocol.SHA256WithECDSA.generate_private_key(), "test-1234"
    )
    with respx.mock(base_url=PLATFORM_URL) as respx_mock:
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
        with pytest.raises(EntityAlreadyExists) as excinfo:
            client.put(client.identity.public_identity, request_id="1234567")
        assert str(excinfo.value) == "identity 'test-1234' already exists"
        assert excinfo.value.request_id == "1234567"
        # TODO: provide the error list


@respx.mock
@pytest.mark.errortest
def test_raise_on_request_error(client: Client) -> None:
    """If raise exception on a request error."""
    respx.put(
        re.compile(PLATFORM_URL + "/api/v1/requests/.*$"),
        content=httpcore.ConnectError(),
    )

    # TODO: do we really want to leak httpx to our clients?
    # We could catch all exception thrown by httpx, wrap it in a few library
    # exceptions and rethrow those.
    with pytest.raises(httpx.ConnectError):
        client.put(client.identity.public_identity)
