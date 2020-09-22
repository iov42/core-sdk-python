"""Test cases for the CryptoBackend module."""
from typing import Type

import pytest

from iov42.core import CryptoProtocol
from iov42.core import generate_private_key
from iov42.core import InvalidSignature
from iov42.core import load_private_key
from iov42.core._crypto import CryptoProtocolInterface
from iov42.core._crypto import load_public_key
from iov42.core._crypto import PrivateKey
from iov42.core._crypto import PublicKey

"""Tuples of golden test data against which we are going to compare.

The tuple consists of (crypto.Protocol, secret_key_base64, public_key, signature, data).
The keys and signature string are provided as used in the iov42 platform (Base64
URL encoded).
"""
golden_data = [
    (
        CryptoProtocol.SHA256WithRSA,
        (
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCEebtBGmMBjT7obvJW"
            "ZDbLf7N_x5XtRja7bZ9Pqm-m9qUXh2nFtoSrc80mmzorHTz-4PuFkJ-WEx-TCLKqIY-8"
            "aQZUtr109FHWuoAqDJjDeJJA49HX0X_08KyXCypK15IZ1wO7DfmENmP5MttTFjeR4pnp"
            "uN1BFopuuNNJpGYDaBW4eq_G4oTIuMS_vu9AnSXidltN7yk2tyDW6dSae4GHJ6FzEpvX"
            "HE-eSGH4TW6FKzxdqZd54xgJ22y04JOnhGeiuiBvLgaZaOh-1RSiHDl1Qqt6RNS-5McI"
            "OAWL2OM7IPP7HthJJWQXIaHAljRUg-1Roe9GYQKTjjA4_UPZLIL5AgMBAAECggEAM0CR"
            "ZKebxD7sJqq90RSmama2gGosJAc1J6BKsVykI7lqt8ao8lghzd9YcGY_w-xk68sJJGyG"
            "gV5WqeEElnOzk1Yin-WvOK9JdkTjTuFevMlJ9Bbv2Ypw8cenTiyAqUHrgVnBVL4cWb1d"
            "Qk0ds3B2AVfk6hqeZw8ccafJ_sS-vvQVmmZ5Mb85tdgyBESuyi6_PkuX8LL0sgtfn8WX"
            "vM5EgNIMl-zQ2vybKUzFXIS32tyFiCWb8l7xvPe_vMQ-kO65uBLSSbDGl2SKDQX9aTAx"
            "S2kw6d396S1pe-ArxEMD2peig8SvrhoJIp8uRQ3b4D-YWaLiyGB9WelYA1rEvr3AcQKB"
            "gQDgnpnSaZ-AnVmnabF-eUDRwkSQbUZ23PLjdWjO20abnIHBxb6oFQuyNfwFpjD5G3qy"
            "4L-B9H-vXlZrl_XH-MBdtfJZmHnv_Wn4NHovPKO59PPKSXDoCv6BWftqRr21ANKPEgu5"
            "IVaixbnXpSKJDCTuKqmZWwdeoraMx7VSBkiA3QKBgQCW-6X3DtjdpmuLgYBW7shWidZQ"
            "jdEzS3BR5-XkiPpDjUTM8rU0gn3rYnaOz6GzN_MmkIVHRHAUO5fwQaizItA_xbNy1F7Z"
            "iHzjvBKuPJfsiee1gxswWTK_WifPowRhl-B4mtqlkF8GAkE4sXda5Gt4VveQZXdTxP7q"
            "Q2d3HUR6zQKBgQC0KqLpIi19BTk_Tki_UFTMqw1B51SozKrKBYfOvBVTheKSYaF-wnrC"
            "NAj1IwuPFBqD1j_l5g5wxLN-08Gh54Ws5N8CPIo6FELmgnkq4HHXG4JcVDIK_Z6MdHd0"
            "FE_gGkvJ1Eiw8uvB3eUl8l_UG3iXzIKC7n_nyY2xOBLZOw72xQKBgQCEiV-FYvkoiYB6"
            "tDGvHmmq3dDOYc-1EZIFtGXwmfXm-snch2peL_bNfF_KuaWep4zA27jDeOZSPIYCGAE5"
            "T2Qztx7xvE-O8euAFobngLV0pRJMGkzxwjt0EnZEJTwhV6tq87TgBb4EjlImrFKz7TQS"
            "LXWgwhFf7dxAVO8sdvq4OQKBgAw6-GQcOwknRa5T0EHGyxgrjdizc_R-SVflbPUYcAm4P"
            "sS9AjLVBe04jZvj5eu9zWsq3cJEGS6ez-zc-bRQKU4XmzHGVln5sjH-ERJurL8mcV2zx"
            "hXRN_b5pUk-RD_du47PeC2G9f2yiVtOSZrK4LH_7hLrA17IYVgIlC0ihD2x"
        ),
        (
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhHm7QRpjAY0-6G7yVmQ2y3-z"
            "f8eV7UY2u22fT6pvpvalF4dpxbaEq3PNJps6Kx08_uD7hZCflhMfkwiyqiGPvGkGVLa9"
            "dPRR1rqAKgyYw3iSQOPR19F_9PCslwsqSteSGdcDuw35hDZj-TLbUxY3keKZ6bjdQRaK"
            "brjTSaRmA2gVuHqvxuKEyLjEv77vQJ0l4nZbTe8pNrcg1unUmnuBhyehcxKb1xxPnkhh"
            "-E1uhSs8XamXeeMYCdtstOCTp4Rnorogby4GmWjoftUUohw5dUKrekTUvuTHCDgFi9jj"
            "OyDz-x7YSSVkFyGhwJY0VIPtUaHvRmECk44wOP1D2SyC-QIDAQAB"
        ),
        (
            "Js-sQ7LfHyXM5wRcEj-v4v3ImI_EaGdjMomv9kjeWZ7dbEe_Hz2yGVm6sDrGAjdt-t4T"
            "KOWNVvicj0rcQx36K4C-1xF3PjX3yIoXMvx0y5u83SSPGI4DFOaofrAK0LuDcU2MUNt8"
            "uYaEbvVk9kVdQLELeFUWtKiaw8tPINlVq9BqBiGk2lXc2lgVuT8hmWf6t9CPg2g1ouBe"
            "9nhRAI7dlBqpZadXahjH1ACEePpnKVABzgMxk7I0i4vbyYARjARJgVN--b39B33yUip5"
            "jB2Gs9oPKCxZsl4iZseUTkXNppiVAWekHNPM2PMPJAehDKkLsdvdtWlJ1btf__V3jFKR8Q"
        ),
        b"Test",
    ),
    (
        CryptoProtocol.SHA256WithECDSA,
        (
            "MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgipzFXWZtCjdTTnEA"
            "lpP2zrAfWIas6u5f9yBs7EGDSF6hRANCAAQ1HLM7jw0wzDpCWomJLrEv4eFv"
            "wK82htsv22T1ljZYPNxMe2nCU9CSbMBrI30oc0wKmfyT9JJNDTzeXX_4FwVr"
        ),
        (
            "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAENRyzO48NMMw6QlqJiS6xL-Hhb8C"
            "vNobbL9tk9ZY2WDzcTHtpwlPQkmzAayN9KHNMCpn8k_SSTQ083l1_-BcFaw"
        ),
        (
            "MEYCIQC_tEPGNJUSsaDC9PsT2zIkaLs1Ik3QL7oESnsx9XLtjQIhAKCO9GdisLzIcK4KcfsmmT9QMGVmYaULEKGcCiCy96RZ"
        ),
        b"Test",
    ),
]


@pytest.mark.parametrize("crypto_protocol_name", ["SHA256WithRSA", "SHA256WithECDSA"])
def test_key_usage(crypto_protocol_name: str) -> None:
    """Generate keys, sign and verify previously created signature."""
    private_key = generate_private_key(crypto_protocol_name)
    public_key = private_key.public_key()
    data = b"Some randome data we would like to sign"
    signature = private_key.sign(data)

    try:
        # Passing the method without error means the signature is valid.
        public_key.verify_signature(signature, data)
    except InvalidSignature:
        pytest.fail("Should not raise InvalidSignature")


@pytest.mark.parametrize(
    "crypto_protocol", [CryptoProtocol.SHA256WithRSA, CryptoProtocol.SHA256WithECDSA]
)
def test_create_key_with_interface(
    crypto_protocol: Type[CryptoProtocolInterface],
) -> None:
    """Generated private key contains its crypto protocol."""
    private_key = generate_private_key(crypto_protocol)

    assert private_key.protocol == crypto_protocol


def test_generate_key_with_unknown_protocol() -> None:
    """Raises ValueError exception for key generation with unknown crypto protocol."""
    unknown_crypto_protocol = "SHA256WithNothing"
    with pytest.raises(ValueError) as excinfo:
        generate_private_key(unknown_crypto_protocol)
    assert f"unknown crypto protocol '{unknown_crypto_protocol}'" in str(excinfo.value)


@pytest.mark.parametrize("crypto_protocol_name", ["SHA256WithRSA", "SHA256WithECDSA"])
def test_protocol_name(crypto_protocol_name: str) -> None:
    """Crypto protocol name matches its string representation."""
    private_key = generate_private_key(crypto_protocol_name)

    assert str(private_key.protocol.name) == crypto_protocol_name


@pytest.mark.parametrize("crypto_protocol_name", ["SHA256WithRSA", "SHA256WithECDSA"])
def test_public_key_protocol(crypto_protocol_name: str) -> None:
    """Generated public key has its correct crypto protocol."""
    private_key = generate_private_key(crypto_protocol_name)
    public_key = private_key.public_key()

    assert public_key.protocol.name == crypto_protocol_name


@pytest.mark.parametrize(
    "used_protocol,_0,public_key_base64,_1,_2",
    golden_data,
)
def test_public_key_serialize(
    used_protocol: CryptoProtocolInterface,
    _0: str,
    public_key_base64: str,
    _1: str,
    _2: bytes,
) -> None:
    """Deserializes and serialize public key from/to platform representation."""
    public_key = load_public_key(public_key_base64)
    assert type(public_key) is PublicKey
    assert public_key.protocol == used_protocol  # type: ignore[comparison-overlap]

    key_serialized = public_key.dump()
    assert public_key_base64 == key_serialized


@pytest.mark.parametrize(
    "used_protocol,private_key_base64,_0,_1,_2",
    golden_data,
)
def test_private_key_serialization(
    used_protocol: CryptoProtocolInterface,
    private_key_base64: str,
    _0: str,
    _1: str,
    _2: bytes,
) -> None:
    """Deserializes and serialize private key from/to platform representation."""
    private_key = load_private_key(private_key_base64)
    assert type(private_key) is PrivateKey
    assert used_protocol == private_key.protocol  # type: ignore[comparison-overlap]

    key_serialized = private_key.dump()
    assert private_key_base64 == key_serialized


@pytest.mark.parametrize(
    "_0,private_key_base64, _1,_2,data",
    golden_data,
    ids=["SHA256WithRSA", "SHA256WithECDSA"],
)
def test_sign(
    _0: CryptoProtocolInterface,
    private_key_base64: str,
    _1: str,
    _2: str,
    data: bytes,
) -> None:
    """Signs data and verifies signature using deserialized keys from reference data."""
    private_key = load_private_key(private_key_base64)
    public_key = private_key.public_key()
    signature = private_key.sign(data)

    assert type(signature) is str
    try:
        # Passing the method without error means the signature is valid.
        public_key.verify_signature(signature, data)
    except InvalidSignature:
        pytest.fail("Should not raise InvalidSignature")


@pytest.mark.parametrize(
    "_0,_1,public_key_base64,signature_base64,data",
    golden_data,
    ids=["SHA256WithRSA", "SHA256WithECDSA"],
)
def test_verify_signature(
    _0: CryptoProtocolInterface,
    _1: str,
    public_key_base64: str,
    signature_base64: str,
    data: bytes,
) -> None:
    """Verify valid signatures of supported crypto protocols."""
    public_key = load_public_key(public_key_base64)
    try:
        # Passing the method without error means the signature is valid.
        public_key.verify_signature(signature_base64, data)
    except InvalidSignature:
        pytest.fail("Should not raise InvalidSignature")


@pytest.mark.parametrize(
    "_0,_1, public_key_base64,signature_base64,data",
    golden_data,
    ids=["SHA256WithRSA", "SHA256WithECDSA"],
)
def test_verify_signature_invalid(
    _0: CryptoProtocolInterface,
    _1: str,
    public_key_base64: str,
    signature_base64: str,
    data: bytes,
) -> None:
    """Throw exception if validation of signature fails."""
    public_key = load_public_key(public_key_base64)
    invalid_signature = "Z" + signature_base64[1:]

    with pytest.raises(InvalidSignature):
        public_key.verify_signature(invalid_signature, data)
