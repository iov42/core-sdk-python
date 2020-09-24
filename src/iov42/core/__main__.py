"""Command-line interface."""
import json
import uuid

import click

from iov42.core import Client
from iov42.core import CryptoProtocol
from iov42.core import generate_private_key
from iov42.core import Identity


@click.group()
@click.version_option()
@click.option(
    "--url",
    default="https://api.sandbox.iov42.dev",
    help="URL of the iov42 platform.",
    show_default=True,
)
@click.option(
    "--request-id",
    default=str(uuid.uuid4()),
    help="Unique identifier associated with the request. [default: generated UUID v4]",
)
@click.pass_context
def cli(ctx: click.core.Context, url: str, request_id: str) -> None:
    """Python library for convenient access to the iov42 platform.."""
    ctx.ensure_object(dict)
    # TODO: lazy creation of identity for the 'create identity' command. For now
    # we provide a dummy identity which will replaced at a later stage.
    dummy_identity = Identity(CryptoProtocol.SHA256WithECDSA.generate_private_key())
    ctx.obj["client"] = Client(url, dummy_identity)
    ctx.obj["request_id"] = request_id


@cli.group()
def create() -> None:
    """Create entities on the iov42 platform."""
    pass


@create.command("identity")
@click.option(
    "--identity-id",
    default=str(uuid.uuid4()),
    help="Identity identifier for the identity being created. [default: generated UUID v4]",
)
@click.option(
    "--crypto-protocol",
    type=click.Choice(["SHA256WithRSA", "SHA256WithECDSA"], case_sensitive=False),
    default="SHA256WithECDSA",
    show_default=True,
    help="Crypto protocol to be used to generate the credentials.",
)
@click.pass_context
def create_identity(
    ctx: click.core.Context, identity_id: str, crypto_protocol: str
) -> None:
    """Create an identity."""
    private_key = generate_private_key(crypto_protocol)
    identity = Identity(private_key, identity_id)

    client = ctx.obj["client"]
    client.identity = identity
    _ = client.create_identity(ctx.obj["request_id"])

    # TODO: should we use click.echo here?
    print(_identity_json(identity))


# TODO: make Identity de/serializer
def _identity_json(identity: Identity) -> str:
    """Create JSON representation of an identity."""
    identity_dict = {
        "identity_id": identity.identity_id,
        "private_key": identity.private_key.dump(),
    }
    return json.dumps(identity_dict)


def main() -> None:
    """Python library for convenient access to the iov42 platform.."""
    cli(obj={})  # pragma: no cover


if __name__ == "__main__":
    main()  # pragma: no cover
