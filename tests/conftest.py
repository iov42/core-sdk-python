"""Test data fixtures shared by different modules."""
import json
import re
from typing import Generator

import pytest
import respx

from iov42.core import Client
from iov42.core import Identity
from iov42.core import load_private_key
from iov42.core import PrivateKey


@pytest.fixture
def private_key() -> PrivateKey:
    """Mock credentials."""
    private_key = load_private_key(
        "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCEebtBGmMBjT7obvJWZDbLf7N_x5X"
        "tRja7bZ9Pqm-m9qUXh2nFtoSrc80mmzorHTz-4PuFkJ-WEx-TCLKqIY-8aQZUtr109FHWuoAqDJjDeJ"
        "JA49HX0X_08KyXCypK15IZ1wO7DfmENmP5MttTFjeR4pnpuN1BFopuuNNJpGYDaBW4eq_G4oTIuMS_v"
        "u9AnSXidltN7yk2tyDW6dSae4GHJ6FzEpvXHE-eSGH4TW6FKzxdqZd54xgJ22y04JOnhGeiuiBvLgaZ"
        "aOh-1RSiHDl1Qqt6RNS-5McIOAWL2OM7IPP7HthJJWQXIaHAljRUg-1Roe9GYQKTjjA4_UPZLIL5AgM"
        "BAAECggEAM0CRZKebxD7sJqq90RSmama2gGosJAc1J6BKsVykI7lqt8ao8lghzd9YcGY_w-xk68sJJG"
        "yGgV5WqeEElnOzk1Yin-WvOK9JdkTjTuFevMlJ9Bbv2Ypw8cenTiyAqUHrgVnBVL4cWb1dQk0ds3B2A"
        "Vfk6hqeZw8ccafJ_sS-vvQVmmZ5Mb85tdgyBESuyi6_PkuX8LL0sgtfn8WXvM5EgNIMl-zQ2vybKUzF"
        "XIS32tyFiCWb8l7xvPe_vMQ-kO65uBLSSbDGl2SKDQX9aTAxS2kw6d396S1pe-ArxEMD2peig8Svrho"
        "JIp8uRQ3b4D-YWaLiyGB9WelYA1rEvr3AcQKBgQDgnpnSaZ-AnVmnabF-eUDRwkSQbUZ23PLjdWjO20"
        "abnIHBxb6oFQuyNfwFpjD5G3qy4L-B9H-vXlZrl_XH-MBdtfJZmHnv_Wn4NHovPKO59PPKSXDoCv6BW"
        "ftqRr21ANKPEgu5IVaixbnXpSKJDCTuKqmZWwdeoraMx7VSBkiA3QKBgQCW-6X3DtjdpmuLgYBW7shW"
        "idZQjdEzS3BR5-XkiPpDjUTM8rU0gn3rYnaOz6GzN_MmkIVHRHAUO5fwQaizItA_xbNy1F7ZiHzjvBK"
        "uPJfsiee1gxswWTK_WifPowRhl-B4mtqlkF8GAkE4sXda5Gt4VveQZXdTxP7qQ2d3HUR6zQKBgQC0Kq"
        "LpIi19BTk_Tki_UFTMqw1B51SozKrKBYfOvBVTheKSYaF-wnrCNAj1IwuPFBqD1j_l5g5wxLN-08Gh5"
        "4Ws5N8CPIo6FELmgnkq4HHXG4JcVDIK_Z6MdHd0FE_gGkvJ1Eiw8uvB3eUl8l_UG3iXzIKC7n_nyY2x"
        "OBLZOw72xQKBgQCEiV-FYvkoiYB6tDGvHmmq3dDOYc-1EZIFtGXwmfXm-snch2peL_bNfF_KuaWep4z"
        "A27jDeOZSPIYCGAE5T2Qztx7xvE-O8euAFobngLV0pRJMGkzxwjt0EnZEJTwhV6tq87TgBb4EjlImrF"
        "Kz7TQSLXWgwhFf7dxAVO8sdvq4OQKBgAw6-GQcOwknRa5T0EHGyxgrjdizc_R-SVflbPUYcAm4PsS9A"
        "jLVBe04jZvj5eu9zWsq3cJEGS6ez-zc-bRQKU4XmzHGVln5sjH-ERJurL8mcV2zxhXRN_b5pUk-RD_d"
        "u47PeC2G9f2yiVtOSZrK4LH_7hLrA17IYVgIlC0ihD2x"
    )
    return private_key


@pytest.fixture
def identity(private_key: PrivateKey) -> Identity:
    """Mock identity."""
    return Identity(private_key, "itest-id-0a9ad8d5-cb84-4f3d-ae7b-94687fe4d7a0")


@pytest.fixture
def client(identity: Identity) -> Client:
    """Client for easy access to iov42 platform."""
    return Client("https://api.sandbox.iov42.dev", identity)


@pytest.fixture
def mocked_create_identity() -> Generator[respx.MockTransport, None, None]:
    """Client for easy access to iov42 platform."""
    with respx.mock(base_url="https://api.sandbox.iov42.dev") as respx_mock:
        respx_mock.put(
            re.compile("/api/v1/requests/.*$"),
            status_code=200,
            alias="create_identity",
            content=json.dumps(
                {
                    "requestId": "e9c79db4-2b8b-439f-95f5-7574005458ef",
                    "resources": [
                        "/api/v1/identities/itest-id-0a9ad8d5-cb84-4f3d-ae7b-94687fe4d7a0"
                    ],
                    "proof": "/api/v1/proofs/e9c79db4-2b8b-439f-95f5-7574005458ef",
                }
            ),
        )
        yield respx_mock
