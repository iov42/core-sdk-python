"""Test data fixtures shared by different modules."""
import json
import re
from typing import Dict
from typing import Generator
from typing import List
from typing import Union

import httpx
import pytest
import respx

from iov42.core import Client
from iov42.core import CryptoProtocol
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
    return Identity(private_key)


@pytest.fixture
def endorser() -> Identity:
    """Mock an identity used to endorse claims on different entities."""
    return Identity(CryptoProtocol.SHA256WithECDSA.generate_private_key())


@pytest.fixture
def client(identity: Identity) -> Client:
    """Client for easy access to iov42 platform."""
    return Client("https://api.vienna-integration.poc.iov42.net", identity)


def entity_created_response(
    request: httpx.Request, req_id: str
) -> Dict[str, Union[str, List[str]]]:
    """Simualate response for creating an entity."""
    content = json.loads(request.read())
    response: Dict[str, Union[str, List[str]]] = {
        "requestId": req_id,
        "proof": "/api/v1/proofs/" + req_id,
    }
    if content["_type"] == "IssueIdentityRequest":
        response["resources"] = ["/api/v1/identities/" + content["identityId"]]
    elif content["_type"] == "DefineAssetTypeRequest":
        response["resources"] = ["/api/v1/asset-types/" + content["assetTypeId"]]
    elif content["_type"] == "CreateAssetRequest":
        response["resources"] = [
            "/".join(
                (
                    "/api/v1/asset-types",
                    content["assetTypeId"],
                    "assets",
                    content["assetId"],
                )
            )
        ]
    elif content["_type"] == "CreateIdentityClaimsRequest":
        response["resources"] = [
            "/".join(
                (
                    "/api/v1/identities",
                    content["subjectId"],
                    "claims",
                    claim,
                )
            )
            for claim in [*content["claims"]]
        ]
    elif content["_type"] == "CreateIdentityEndorsementsRequest":
        response["resources"] = [
            "/".join(
                (
                    "/api/v1/identities",
                    content["subjectId"],
                    "claims",
                    claim,
                    "endorsements",
                    content["endorserId"],
                )
            )
            for claim in [*content["endorsements"]]
        ]
    elif content["_type"] == "CreateAssetTypeClaimsRequest":
        response["resources"] = [
            "/".join(
                (
                    "/api/v1/asset-types",
                    content["subjectId"],
                    "claims",
                    claim,
                )
            )
            for claim in [*content["claims"]]
        ]
    elif content["_type"] == "CreateAssetTypeEndorsementsRequest":
        response["resources"] = [
            "/".join(
                (
                    "/api/v1/asset-types",
                    content["subjectId"],
                    "claims",
                    claim,
                    "endorsements",
                    content["endorserId"],
                )
            )
            for claim in [*content["endorsements"]]
        ]
    elif content["_type"] in ["CreateAssetClaimsRequest"]:
        response["resources"] = [
            "/".join(
                (
                    "/api/v1/asset-types",
                    content["subjectTypeId"],
                    "assets",
                    content["subjectId"],
                    "claims",
                    claim,
                )
            )
            for claim in [*content["claims"]]
        ]
    elif content["_type"] in ["CreateAssetEndorsementsRequest"]:
        response["resources"] = [
            "/".join(
                (
                    "/api/v1/asset-types",
                    content["subjectTypeId"],
                    "assets",
                    content["subjectId"],
                    "claims",
                    claim,
                    "endorsements",
                    content["endorserId"],
                )
            )
            for claim in [*content["endorsements"]]
        ]
    else:
        raise NotImplementedError("mocked service - unknown _type: " + content["_type"])

    return response


@pytest.fixture
def mocked_requests_200() -> Generator[respx.MockTransport, None, None]:
    """Client for easy access to iov42 platform."""
    with respx.mock(
        base_url="https://api.vienna-integration.poc.iov42.net", assert_all_called=False
    ) as respx_mock:
        respx_mock.put(
            re.compile("/api/v1/requests/(?P<req_id>[^ ].*)$"),
            status_code=200,
            alias="create_entity",
            content=entity_created_response,
        )
        respx_mock.get(
            re.compile(
                "/api/v1/asset-types/(?P<asset_type_id>.*)/assets/(?P<asset_id>.*)"
                "/claims/(?P<hashed_claim>.*)/endorsements/(?P<endorser_id>.*)"
                "?requestId=(?P<request_id>.*)&nodeId=(?P<node_id>[^ ].*)$"
            ),
            status_code=200,
            alias="read_asset_endorsement",
            content=endorsement_response,
        )
        respx_mock.get(
            "/api/v1/node-info",
            status_code=200,
            alias="read_node_info",
            content='{"nodeId":"node-1","publicCredentials":{"key":"value","protocolId":"SHA256WithRSA"}}',
        )
        yield respx_mock


def endorsement_response(
    request: httpx.Request,
    asset_type_id: str,
    asset_id: str,
    hashed_claim: str,
    endorser_id: str,
    request_id: str,
    node_id: str,
) -> Dict[str, Union[str, List[str]]]:
    """Simualate response for creating an entity."""
    response: Dict[str, Union[str, List[str]]] = {
        "proof": "/api/v1/proofs/" + "some-random-proof-id",
        "endorserId": endorser_id,
        "endorsement": "mock-endorsement-value",
    }
    return response
