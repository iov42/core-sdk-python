"""Entities of the iov42 platform."""
import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from typing import cast
from typing import Optional
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from ._client import Request
from ._crypto import iov42_encode
from ._crypto import PrivateKey

# TODO: can we convert this to data classes?

Identifier = str


def hashed_claim(claim: bytes) -> bytes:
    """Returns the hashed claim."""
    return iov42_encode(hashlib.sha256(claim).digest())


@dataclass(frozen=True)
class Claim:
    """Claims on the iov42 platform."""

    data: bytes

    @property
    def hash(self) -> str:
        """Hashed representation of a claim."""
        return hashed_claim(self.data).decode()


invalid_chars = re.compile(r"[^a-zA-Z0-9._\-+]")


def assure_valid_identifier(id: Identifier, generate_id: bool = True) -> Identifier:
    """Makes sure the identifier contains only valid characters.

    Args:
        id: identifier to be validated.
        generate_id: if True generate an identifier if id is empty, otherwise raise ValueError.

    Returns:
        A valid idenfier.

    Raises:
        ValueError: in case the idenfier contains invalid characters.
    """
    if id and not invalid_chars.search(id):
        return id
    if not id and generate_id:
        return str(uuid.uuid4())
    raise ValueError(
        f"invalid identifier '{id}' - "
        f"valid characters are {invalid_chars.pattern.replace('^', '')}"
    )


class Identity:
    """Identity used to sign the requests."""

    def __init__(self, private_key: PrivateKey, identity_id: Identifier = "") -> None:
        """Create new identity.

        Args:
            private_key: the identiy private key used for authentication.
            identity_id: the identifier of the identity.

        Raises:
            TypeError: if the povided key is not a PrivateKey.

            ValueError: if id contains invalid characters.
        """
        self.identity_id = assure_valid_identifier(identity_id)
        if not isinstance(private_key, PrivateKey):
            raise TypeError(f"must be PrivateKey, not {type(private_key).__name__}")
        self.private_key = private_key

    @property
    def resource(self) -> str:
        """Relative path where information about the identity can be read."""
        return "/".join(("/api/v1/identities", self.identity_id))

    def sign(self, content: bytes) -> str:
        """Signs content with private key.

        Args:
            content: content for which the signature

        Returns:
            Signature of the content signed with the private key.
        """
        return self.private_key.sign(content)

    def verify_signature(self, signature: str, data: bytes) -> None:
        """Verify one block of data was signed by the identiy.

        Args:
            signature: Signature to verify as Base64 encoded string.
            data: The data for which the signature

        Raises:
            InvalidSignature if the verification failed.
        """
        self.private_key.public_key().verify_signature(signature, data)

    def request_content(self, request: "Request") -> str:
        """Create request content."""
        return json.dumps(
            {
                "_type": "IssueIdentityRequest",
                "identityId": self.identity_id,
                "publicCredentials": {
                    "key": self.private_key.public_key().dump(),
                    "protocolId": self.private_key.protocol.name,
                },
                "requestId": request.request_id,
            },
            separators=(",", ":"),
        )


class AssetType:
    """Status of a previously submitted request."""

    def __init__(
        self, asset_type_id: Identifier = "", *, scale: Optional[int] = None
    ) -> None:
        """Creates an asset type.

        Args:
            asset_type_id: the identifier of the asset type.
            scale: whether instance of this asset type are entities or quantities.

        Raises:
            ValueError if the given id contains invalid characters.
        """
        self.asset_type_id = assure_valid_identifier(asset_type_id)
        self.type = "Quantifiable" if scale else "Unique"

    @property
    def resource(self) -> str:
        """Relative path where information about the asset type can be read."""
        return "/".join(("/api/v1/asset-types", self.asset_type_id))

    def request_content(self, request: "Request") -> str:
        """Create request content."""
        content = json.dumps(
            {
                "_type": "DefineAssetTypeRequest",
                "assetTypeId": self.asset_type_id,
                "type": self.type,
                "requestId": request.request_id,
            }
        )
        return content


class Asset:
    """Status of a previously submitted request."""

    def __init__(self, *, asset_type_id: Identifier, asset_id: Identifier = "") -> None:
        """Creates an asset.

        Args:
            asset_type_id: the identifier of the asset type of which the new asset will belong.
            asset_id: the identifier of the asset.

        Raises:
            ValueError if one of the given identifiers contains invalid characters.
        """
        self.asset_type_id = assure_valid_identifier(asset_type_id, generate_id=False)
        self.asset_id = assure_valid_identifier(asset_id)

    @property
    def resource(self) -> str:
        """Relative path where information about the asset can be read."""
        return "/".join(
            ("/api/v1/asset-types", self.asset_type_id, "assets", self.asset_id)
        )

    def request_content(self, request: "Request") -> str:
        """Create request content to create an asset or asset claims."""
        if request.endorser:
            endorser = cast(Identity, request.endorser)
            content = json.dumps(
                {
                    "_type": "CreateAssetEndorsementsRequest",
                    "subjectId": self.asset_id,
                    "subjectTypeId": self.asset_type_id,
                    "endorserId": endorser.identity_id,
                    "endorsements": {
                        c.hash: endorser.sign(
                            ";".join(
                                (self.asset_id, self.asset_type_id, c.hash)
                            ).encode()
                        )
                        for c in request.claims
                    },
                    "requestId": request.request_id,
                }
            )
        else:
            content = json.dumps(
                {
                    "_type": "CreateAssetRequest",
                    "assetId": self.asset_id,
                    "assetTypeId": self.asset_type_id,
                    "requestId": request.request_id,
                }
            )
        return content
