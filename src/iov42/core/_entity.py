"""Entities of the iov42 platform."""
import dataclasses
import hashlib
import json
import re
import uuid
from typing import cast
from typing import Optional
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from ._request import Request
from ._crypto import iov42_encode
from ._crypto import PrivateKey

# TODO: can we convert this to data classes?

Identifier = str


def generate_id() -> Identifier:
    """Generate ID if none is provided."""
    return str(uuid.uuid4())


def hashed_claim(claim: bytes) -> bytes:
    """Returns the hashed claim."""
    return iov42_encode(hashlib.sha256(claim).digest())


@dataclasses.dataclass(frozen=True)
class Claim:
    """Claims on the iov42 platform."""

    data: bytes

    @property
    def hash(self) -> str:
        """Hashed representation of a claim."""
        return hashed_claim(self.data).decode()


invalid_chars = re.compile(r"[^a-zA-Z0-9._\-+]")


@dataclasses.dataclass(frozen=True)
class Identity:
    """Identity used to sign the requests."""

    private_key: PrivateKey = dataclasses.field(repr=False)
    identity_id: Identifier = dataclasses.field(default_factory=generate_id)

    def __post_init__(self) -> None:
        """Assure the provided identifier is valid."""
        if invalid_chars.search(self.identity_id):
            raise ValueError(
                f"invalid identifier '{self.identity_id}' - "
                f"valid characters are {invalid_chars.pattern.replace('^', '')}"
            )
        if not isinstance(self.private_key, PrivateKey):
            raise TypeError(
                f"must be PrivateKey, not {type(self.private_key).__name__}"
            )

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


@dataclasses.dataclass(frozen=True)
class AssetType:
    """Status of a previously submitted request."""

    asset_type_id: Identifier = dataclasses.field(default_factory=generate_id)
    scale: Optional[int] = dataclasses.field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Assure the provided identifier is valid."""
        if invalid_chars.search(self.asset_type_id):
            raise ValueError(
                f"invalid identifier '{self.asset_type_id}' - "
                f"valid characters are {invalid_chars.pattern.replace('^', '')}"
            )

    @property
    def type(self) -> str:
        """If the asset type is Quantifiable or Unique."""
        return "Quantifiable" if self.scale else "Unique"

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


@dataclasses.dataclass(frozen=True)
class Asset:
    """Status of a previously submitted request."""

    asset_type_id: Identifier
    asset_id: Identifier = dataclasses.field(default_factory=generate_id)

    def __post_init__(self) -> None:
        """Assure the provided identifier is valid."""
        if not self.asset_type_id or invalid_chars.search(self.asset_type_id):
            raise ValueError(
                f"invalid identifier '{self.asset_type_id}' - "
                f"valid characters are {invalid_chars.pattern.replace('^', '')}"
            )
        if invalid_chars.search(self.asset_id):
            raise ValueError(
                f"invalid identifier '{self.asset_id}' - "
                f"valid characters are {invalid_chars.pattern.replace('^', '')}"
            )

    @property
    def resource(self) -> str:
        """Relative path where information about the asset can be read."""
        return "/".join(
            ("/api/v1/asset-types", self.asset_type_id, "assets", self.asset_id)
        )

    def request_content(self, request: "Request") -> str:
        """Create request content to create an asset or asset claims."""
        if hasattr(request, "endorser"):
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
        elif hasattr(request, "claims"):
            content = json.dumps(
                {
                    "_type": "CreateAssetClaimsRequest",
                    "subjectId": self.asset_id,
                    "subjectTypeId": self.asset_type_id,
                    "claims": [c.hash for c in request.claims],
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
