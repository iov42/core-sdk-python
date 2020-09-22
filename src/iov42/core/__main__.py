"""Command-line interface."""
import click


@click.command()
@click.version_option()
def main() -> None:
    """Python library for convenient access to the iov42 platform.."""


if __name__ == "__main__":
    main(prog_name="core")  # pragma: no cover
