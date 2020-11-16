"""Example code how to use iov42.core.Client with multiple theards.

The test data has to be generated before hand by calling `python create-data.py`.
"""
import csv
from concurrent.futures import ThreadPoolExecutor
from typing import List
from typing import Tuple

from iov42.core import Asset
from iov42.core import AssetType
from iov42.core import Client
from iov42.core import CryptoProtocol
from iov42.core import PrivateIdentity


def register_product(
    client: Client, tag_type: AssetType, product: Tuple[str, str]
) -> None:
    """Register product on iov42 platform and add product information as claim."""
    tag_id, claim = product
    tag = Asset(asset_id=tag_id, asset_type_id=tag_type.asset_type_id)
    client.put(tag)
    print(f"Created tag: {tag_id}")
    client.put(tag, claims=[claim.encode()], endorse=True)
    print(f"Tag [{tag_id}]: added enrosement on claim '{claim}'")


def read_product_data(filename: str) -> List[Tuple[str, str]]:
    """Reads product information from file."""
    with open(filename) as fp:
        reader = csv.reader(fp, delimiter=";")
        next(reader, None)  # skip the header
        products = [tuple(row) for row in reader]
    return products


def main() -> None:
    """Create identity, asset type and register products."""
    product_data = read_product_data("nfc-tags.csv")

    # Usually we would store the identity (ID and key) on a safe place.
    manufacturer = PrivateIdentity(
        CryptoProtocol.SHA256WithECDSA.generate_private_key()
    )

    with Client("https://api.vienna-integration.poc.iov42.net", manufacturer) as client:
        # Create the identity
        client.put(manufacturer.public_identity)
        print(f"Created manufacturer identity: {manufacturer.identity_id}")

        # Create the asset typ used for the NFC tags.
        tag_type = AssetType()
        client.put(tag_type)
        print(f"Created tag asset type: {tag_type}")

        # Register the NFC tags on the distributed ledger in parallel.
        with ThreadPoolExecutor(max_workers=20) as executor:
            _ = executor.map(
                register_product,
                [client] * len(product_data),
                [tag_type] * len(product_data),
                product_data,
            )
            executor.shutdown(wait=True)


if __name__ == "__main__":
    main()
