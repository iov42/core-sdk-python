"""Test cases for the __main__ module."""
import pytest
import respx
from click.testing import CliRunner

from iov42.core import __main__


@pytest.fixture
def runner() -> CliRunner:
    """Fixture for invoking command-line interfaces."""
    return CliRunner()


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
    runner: CliRunner, mocked_create_identity: respx.MockTransport
) -> None:
    """It shows create help message."""
    result = runner.invoke(__main__.cli, ["create", "identity"])
    assert result.exit_code == 0
    assert '"identity_id":' in result.output
    assert '"private_key":' in result.output


@pytest.mark.skip(reason="not implemted yet")
def test_main_create_unique_asset_type(
    runner: CliRunner, mocked_create_unique_asset_type: respx.MockTransport
) -> None:
    """Create unique asset type and output it on stdout."""
    result = runner.invoke(__main__.cli, ["create", "asset-type", "--identity", "foo"])
    assert result.exit_code == 0
    assert '"asset_type_id":' in result.output
