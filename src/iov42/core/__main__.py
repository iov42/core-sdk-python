"""Command-line interface."""
import json
import uuid
from typing import List

import click

from iov42.core import Asset
from iov42.core import AssetType
from iov42.core import Client
from iov42.core import generate_private_key
from iov42.core import Identity
from iov42.core import load_private_key

# from iov42.core import AssetType


@click.group()
@click.version_option()
@click.option(
    "--url",
    default="https://api.vienna-integration.poc.iov42.net",
    help="URL of the iov42 platform.",
    show_default=True,
)
@click.option(
    "--request-id",
    default=str(uuid.uuid4()),
    help="Unique identifier associated with the request.  [default: generated UUID v4]",
)
@click.pass_context
def cli(ctx: click.core.Context, url: str, request_id: str) -> None:
    """Python library for convenient access to the iov42 platform.."""
    ctx.ensure_object(dict)
    # TODO: lazy creation of identity for the 'create identity' command. For now
    # we provide a dummy identity which will replaced at a later stage.
    ctx.obj["url"] = url
    ctx.obj["request_id"] = request_id


@cli.group()
def create() -> None:
    """Create entities on the iov42 platform."""
    pass


@create.command("identity")
@click.option(
    "--identity-id",
    default=str(uuid.uuid4()),
    help="Identity identifier for the identity being created.  [default: generated UUID v4]",
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
    client = Client(ctx.obj["url"], identity)

    _ = client.put(identity, request_id=ctx.obj["request_id"])

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


@create.command("asset-type")
# TODO: with the exception of create_identity() we have to provide the
# identity for all calls to the platform. It probably would make sense to
# provide the identity when creating the Client instance.
@click.option(
    "--identity",
    required=True,
    help="Identity used to authenticate on the platform.",
)
@click.option(
    "--asset-type-id",
    default=str(uuid.uuid4()),
    help="The identifier of the asset type being created.  [default: generated UUID v4]",
)
@click.option(
    "--scale",
    type=int,
    help="Maximum number of decimal places for a quantity. If not provided create an unique asset type.",
)
@click.pass_context
def create_asset_type(
    ctx: click.core.Context, identity: str, asset_type_id: str, scale: int
) -> None:
    """Create an asset type."""
    asset_type = AssetType(asset_type_id)
    id = _load_identity(identity)
    client = Client(ctx.obj["url"], id)
    _ = client.put(asset_type, request_id=ctx.obj["request_id"])
    print(f"asset_type_id: {asset_type_id}")


@create.command("asset")
# TODO: with the exception of create_identity() we have to provide the
# identity for all calls to the platform. It probably would make sense to
# provide the identity when creating the Client instance.
@click.option(
    "--identity",
    required=True,
    help="Identity used to authenticate on the platform.",
)
@click.option(
    "--asset-type-id",
    required=True,
    help="The identifier of the asset type the asset belong to.",
)
@click.option(
    "--asset-id",
    default=str(uuid.uuid4()),
    help="The identifier of the asset being created.  [default: generated UUID v4]",
)
@click.pass_context
def create_asset(
    ctx: click.core.Context, identity: str, asset_type_id: str, asset_id: str
) -> None:
    """Create an asset."""
    asset = Asset(asset_type_id=asset_type_id, asset_id=asset_id)
    id = _load_identity(identity)
    client = Client(ctx.obj["url"], id)
    _ = client.put(asset, request_id=ctx.obj["request_id"])
    print(f"asset_id: {asset}")


@create.command("endorsement")
# TODO: with the exception of create_identity() we have to provide the
# identity for all calls to the platform. It probably would make sense to
# provide the identity when creating the Client instance.
@click.option(
    "--identity",
    required=True,
    help="Identity used to authenticate on the platform.",
)
@click.option(
    "--entity-type",
    required=True,
    type=click.Choice(["identity", "asset-type", "asset"], case_sensitive=False),
    help="The entity type which the endorsemen is created.",
)
@click.option(
    "--entity-id",
    required=True,
    help="The identifier of the entity for which the claims are endorsed.",
)
@click.option(
    "--asset-type-id",
    help="The identifier of the asset type the asset belongs.",
)
@click.argument(
    "claims",
    required=True,
    nargs=-1,
)
@click.pass_context
def create_endorsement(
    ctx: click.core.Context,
    identity: str,
    entity_type: str,
    entity_id: str,
    asset_type_id: str,
    claims: List[str],
) -> None:
    """Endorse claims about an entity (identity, asset type, unique asset)."""
    if entity_type.lower() == "asset":
        entity = Asset(asset_type_id=asset_type_id, asset_id=entity_id)
    else:
        raise NotImplementedError  # pragma: no cover
    id = _load_identity(identity)
    client = Client(ctx.obj["url"], id)
    claims_bytes = [c.encode() for c in claims]
    response = client.put(
        entity, claims=claims_bytes, endorse=True, request_id=ctx.obj["request_id"]
    )
    print(f"claims on {entity}: {entity_id}")
    print(f"affected resources: {response.resources}")  # type: ignore[attr-defined]


@cli.group()
def read() -> None:
    """Read information stord on the iov42 platform."""
    # TODO - disable coverage check until implemented
    pass  # pragma: no cover


@read.command("endorsement")
# TODO: with the exception of create_identity() we have to provide the
# identity for all calls to the platform. It probably would make sense to
# provide the identity when creating the Client instance.
@click.option(
    "--identity",
    required=True,
    help="Identity used to authenticate on the platform.",
)
@click.option(
    "--endorser-id",
    required=True,
    help="Identity who endorsed the claim.",
)
@click.option(
    "--entity-type",
    required=True,
    type=click.Choice(["identity", "asset-type", "asset"], case_sensitive=False),
    help="The entity type which the endorsemen is created.",
)
@click.option(
    "--entity-id",
    required=True,
    help="The identifier of the entity for which the claims are endorsed.",
)
@click.option(
    "--asset-type-id",
    help="The identifier of the asset type the asset belongs.",
)
@click.argument(
    "claim",
    required=True,
    nargs=1,
)
@click.pass_context
def read_endorsement(
    ctx: click.core.Context,
    identity: str,
    endorser_id: str,
    entity_type: str,
    entity_id: str,
    asset_type_id: str,
    claim: str,
) -> None:  # pragma: no cover
    """Read specific endorsement of a claim (identity, asset type, unique asset)."""
    if entity_type.lower() == "asset":
        entity = Asset(asset_type_id=asset_type_id, asset_id=entity_id)
    else:
        raise NotImplementedError  # pragma: no cover
    id = _load_identity(identity)
    client = Client(ctx.obj["url"], id)
    response = client.get(
        entity,
        claim=claim.encode(),
        endorser_id=endorser_id,
        request_id=ctx.obj["request_id"],
    )
    print(f"{entity!r}")
    print(f"{claim!r}")
    print(f"endorser: {response.endorser_id!r}")  # type: ignore[attr-defined]


# TODO: make Identity de/serializer
def _load_identity(identity: str) -> Identity:
    with open(identity) as identity_file:
        id = json.load(identity_file)
        return Identity(load_private_key(id["private_key"]), id["identity_id"])


def main() -> None:
    """Python library for convenient access to the iov42 platform.."""
    cli(obj={})  # pragma: no cover


if __name__ == "__main__":
    main()  # pragma: no cover
