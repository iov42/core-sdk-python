"""Test cases for the __main__ module."""
import json
from typing import Any

import pytest
import respx
from click.testing import CliRunner

from iov42.core import __main__


@pytest.fixture
def runner() -> CliRunner:
    """Fixture for invoking command-line interfaces."""
    return CliRunner()


@pytest.fixture(scope="session")
def identity_file_name(tmpdir_factory: Any) -> str:
    """Create identiy file."""
    file_name = tmpdir_factory.mktemp("identities").join(
        "itest-id-0a9ad8d5-cb84-4f3d-ae7b-94687fe4d7a0.identity"
    )
    content = {
        "identity_id": "itest-id-0a9ad8d5-cb84-4f3d-ae7b-94687fe4d7a0",
        "private_key": (
            "MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgipzFXWZtCjdTTnEA"
            "lpP2zrAfWIas6u5f9yBs7EGDSF6hRANCAAQ1HLM7jw0wzDpCWomJLrEv4eFv"
            "wK82htsv22T1ljZYPNxMe2nCU9CSbMBrI30oc0wKmfyT9JJNDTzeXX_4FwVr"
        ),
    }
    file_name.write(json.dumps(content))
    return str(file_name)


def test_main_succeeds(runner: CliRunner) -> None:
    """It exits with a status code of zero."""
    result = runner.invoke(__main__.cli)
    assert result.exit_code == 0
    output_no_whitespaces = " ".join(result.output.split())
    assert "create Create entities on the iov42 platform." in output_no_whitespaces
    assert "--url TEXT URL of the iov42 platform." in output_no_whitespaces
    assert (
        "--request-id TEXT Unique identifier associated with the request."
        " [default: generated UUID v4]" in output_no_whitespaces
    )


def test_main_show_help_create(runner: CliRunner) -> None:
    """It shows create help message."""
    result = runner.invoke(__main__.cli, ["create"])
    assert result.exit_code == 0
    output_no_whitespaces = " ".join(result.output.split())
    assert "Create entities on the iov42 platform." in output_no_whitespaces
    assert "identity Create an identity" in output_no_whitespaces
    assert "asset-type Create an asset type" in output_no_whitespaces


def test_main_show_help_create_identity(runner: CliRunner) -> None:
    """It shows create identity help message."""
    result = runner.invoke(__main__.cli, ["create", "identity", "--help"])
    assert result.exit_code == 0
    output_no_whitespaces = " ".join(result.output.split())
    assert "Create an identity" in result.output
    assert (
        "--identity-id TEXT Identity identifier for the identity being created."
        " [default: generated UUID v4]" in output_no_whitespaces
    )
    assert (
        "--crypto-protocol [SHA256WithRSA|SHA256WithECDSA]"
        " Crypto protocol to be used to generate the credentials."
        " [default: SHA256WithECDSA]" in output_no_whitespaces
    )


def test_main_create_identity(
    runner: CliRunner, mocked_requests_200: respx.MockTransport
) -> None:
    """Create identity and show identity id with private key on stdout."""
    result = runner.invoke(__main__.cli, ["create", "identity"])
    assert result.exit_code == 0
    assert '"identity_id":' in result.output
    assert '"private_key":' in result.output


def test_main_show_help_create_asset_type(runner: CliRunner) -> None:
    """It shows create asset-type help message."""
    result = runner.invoke(__main__.cli, ["create", "asset-type", "--help"])
    assert result.exit_code == 0
    output_no_whitespaces = " ".join(result.output.split())
    assert "Create an asset type" in output_no_whitespaces
    assert (
        "--identity TEXT Identity used to authenticate on the platform."
        in output_no_whitespaces
    )
    assert (
        "--asset-type-id TEXT"
        " The identifier of the asset type being created. [default: generated UUID v4]"
        in output_no_whitespaces
    )
    assert (
        "--scale INTEGER Maximum number of decimal places for a quantity. If not "
        "provided create an unique asset type." in output_no_whitespaces
    )


def test_main_create_unique_asset_type(
    runner: CliRunner,
    mocked_requests_200: respx.MockTransport,
    identity_file_name: str,
) -> None:
    """Create unique asset type and output it on stdout."""
    result = runner.invoke(
        __main__.cli, ["create", "asset-type", "--identity", str(identity_file_name)]
    )
    assert result.exit_code == 0
    assert "asset_type_id:" in result.output


def test_main_show_help_create_asset(runner: CliRunner) -> None:
    """It shows create identity help message."""
    result = runner.invoke(__main__.cli, ["create", "asset", "--help"])
    assert result.exit_code == 0
    output_no_whitespaces = " ".join(result.output.split())
    assert "Create an asset" in result.output
    assert (
        "--identity TEXT Identity used to authenticate on the platform. [required]"
        in output_no_whitespaces
    )
    assert (
        "--asset-type-id TEXT The identifier of the asset type the asset belong to. [required]"
        in output_no_whitespaces
    )
    assert (
        "--asset-id TEXT The identifier of the asset being created. [default: generated UUID v4]"
        in output_no_whitespaces
    )


def test_main_create_unique_asset(
    runner: CliRunner,
    mocked_requests_200: respx.MockTransport,
    identity_file_name: str,
) -> None:
    """Create unique asset and output it on stdout."""
    result = runner.invoke(
        __main__.cli,
        [
            "create",
            "asset",
            "--identity",
            str(identity_file_name),
            "--asset-type-id",
            "085f2066-d469-4a45-b7d8-b12f145a2e59",
        ],
    )
    assert result.exit_code == 0
    assert "asset_id:" in result.output


def test_main_show_help_create_endorsement(runner: CliRunner) -> None:
    """It shows create identity help message."""
    result = runner.invoke(__main__.cli, ["create", "endorsement", "--help"])
    assert result.exit_code == 0
    output_no_whitespaces = " ".join(result.output.split())
    assert (
        "Endorse claims about an entity (identity, asset type, unique asset)."
        in result.output
    )
    assert (
        "--identity TEXT Identity used to authenticate on the platform. [required]"
        in output_no_whitespaces
    )
    assert (
        "--entity-type [identity|asset-type|asset] The entity type which the "
        "endorsemen is created. [required]" in output_no_whitespaces
    )
    assert (
        "--entity-id TEXT The identifier of the entity for which the claims are endorsed. [required]"
        in output_no_whitespaces
    )
    assert (
        "--asset-type-id TEXT The identifier of the asset type the asset belongs."
        in output_no_whitespaces
    )


def test_main_create_asset_endorsement(
    runner: CliRunner,
    mocked_requests_200: respx.MockTransport,
    identity_file_name: str,
) -> None:
    """Create unique asset and output it on stdout."""
    result = runner.invoke(
        __main__.cli,
        [
            "create",
            "endorsement",
            "--identity",
            str(identity_file_name),
            "--entity-type",
            "asset",
            "--entity-id",
            "43979673-1916-4b81-9a75-de03e48137d4",
            "--asset-type-id",
            "085f2066-d469-4a45-b7d8-b12f145a2e59",
            "name: John Doe;DOB:2000/01/01;LOB:Sidney",
        ],
    )
    assert result.exit_code == 0
    # TODO: what output do we provide here?
    assert (
        "/api/v1/asset-types/085f2066-d469-4a45-b7d8-b12f145a2e59/assets/"
        "43979673-1916-4b81-9a75-de03e48137d4/claims/qkAvEK9gq5vIpxqyQfzthf3yH1Ue_uNon-NNcSZWPP4/endorsements"
        in result.output
    )


def test_main_get_asset_endorsement(
    runner: CliRunner,
    mocked_requests_200: respx.MockTransport,
    identity_file_name: str,
) -> None:
    """Create unique asset and output it on stdout."""
    result = runner.invoke(
        __main__.cli,
        [
            "read",
            "endorsement",
            "--identity",
            str(identity_file_name),
            "--endorser-id",
            "e00408bc-f717-448c-9d4b-9c0da8c41575",
            "--entity-type",
            "asset",
            "--entity-id",
            "43979673-1916-4b81-9a75-de03e48137d4",
            "--asset-type-id",
            "085f2066-d469-4a45-b7d8-b12f145a2e59",
            "name: John Doe;DOB:2000/01/01;LOB:Sidney",
        ],
    )
    assert result.exit_code == 0
    # TODO: what output do we provide here?
    # assert (
    #     "asset(id=43979673-1916-4b81-9a75-de03e48137d4,asset_type=085f2066-d469-4a45-b7d8-b12f145a2e59)"
    #     "claim(text='name: John Doe;DOB:2000/01/01;LOB:Sidney',"
    #     "hash=qkAvEK9gq5vIpxqyQfzthf3yH1Ue_uNon-NNcSZWPP4)"
    #     "endorser: Identity(id='e00408bc-f717-448c-9d4b-9c0da8c41575')" in result.output
    # )
