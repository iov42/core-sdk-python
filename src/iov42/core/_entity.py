"""Entities of the iov42 platform."""
import dataclasses
import hashlib
import json
import re
import typing
import uuid

from ._crypto import iov42_encode
from ._crypto import PrivateKey


Identifier = str


def generate_id() -> Identifier:
    """Generate ID if none is provided."""
    return str(uuid.uuid4())


def hashed_claim(claim: bytes) -> str:
    """Returns the hashed claim in string representation."""
    return iov42_encode(hashlib.sha256(claim).digest()).decode()


invalid_chars = re.compile(r"[^a-zA-Z0-9._\-+]")

ContentDict = typing.Dict[
    str, typing.Union[str, int, typing.Dict[str, str], typing.List[str]]
]


def assure_valid_identifier(id: typing.Optional[Identifier]) -> Identifier:
    """Assures the provided identifier would be accepted by the platform.

    Args:
        id: The identifier to be validated. If empty, a valid identifier is generated.

    Returns:
        A valid identifier.

    Raises:
        ValueError: in case the identifier is not valid.
    """
    if not id:
        return generate_id()
    elif not invalid_chars.search(id):
        return id
    raise ValueError(
        f"invalid identifier '{id}' - "
        f"valid characters are {invalid_chars.pattern.replace('^', '')}"
    )


@dataclasses.dataclass(frozen=True)
class BaseEntity:
    """Status of a previously submitted request."""

    _type: typing.ClassVar[typing.Dict[str, str]] = {}

    @property
    def id(self) -> Identifier:
        """Entity identifier."""
        ...  # pragma: no cover

    def put_request_content(
        self,
        *,
        claims: typing.Optional[typing.List[bytes]] = None,
        endorser: typing.Optional["Identity"] = None,
        request_id: typing.Optional[Identifier] = None,
    ) -> bytes:
        """Create request content."""
        request_id = assure_valid_identifier(request_id)
        if endorser:
            if not claims:
                raise TypeError(
                    "missing required keyword argument needed for endorsement: 'claims'"
                )
            content_dict: ContentDict = {
                "_type": self._type["endorsements"],
                "requestId": request_id,
                "subjectId": self.id,
                "endorserId": endorser.identity_id,
                "endorsements":
                # create_endorsements(
                {
                    hashed_claim(c): endorser.sign(
                        ";".join(self._subject() + [hashed_claim(c)]).encode()
                    )
                    for c in claims
                },
            }
        elif claims:
            content_dict = {
                "_type": self._type["claims"],
                "requestId": request_id,
                "subjectId": self.id,
                "claims": [hashed_claim(c) for c in claims],
            }
        else:
            content_dict = {
                "_type": self._type["entity"],
                "requestId": request_id,
            }
        content_dict.update(self._entity_specific_content(claims, endorser, request_id))
        content = json.dumps(content_dict)
        return content.encode()

    def _subject(self) -> typing.List[str]:
        """Subject to endorse."""
        return [self.id]

    def _entity_specific_content(
        self,
        claims: typing.Optional[typing.List[bytes]] = None,
        endorser: typing.Optional["Identity"] = None,
        request_id: typing.Optional[Identifier] = None,
    ) -> ContentDict:
        ...  # pragma: no cover


@dataclasses.dataclass(frozen=True)
class Identity(BaseEntity):
    """Identity used to sign the requests."""

    private_key: PrivateKey = dataclasses.field(repr=False)
    identity_id: Identifier = dataclasses.field(default_factory=generate_id)
    _type: typing.ClassVar[typing.Dict[str, str]] = {
        "endorsements": "CreateIdentityEndorsementsRequest",
        "claims": "CreateIdentityClaimsRequest",
        "entity": "IssueIdentityRequest",
    }

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
    def id(self) -> Identifier:
        """Entity identifier."""
        return self.identity_id

    @property
    def resource(self) -> str:
        """Relative path where information about the identity can be read."""
        return "/".join(("/api/v1/identities", self.identity_id))

    def _entity_specific_content(
        self,
        claims: typing.Optional[typing.List[bytes]] = None,
        endorser: typing.Optional["Identity"] = None,
        request_id: typing.Optional[Identifier] = None,
    ) -> ContentDict:
        if not claims and not endorser:
            d: ContentDict = {
                "identityId": self.identity_id,
                "publicCredentials": {
                    "key": self.private_key.public_key().dump(),
                    "protocolId": self.private_key.protocol.name,
                },
            }
            return d
        return {}

    def sign(self, content: bytes) -> str:
        """Signs content with private key.

        Args:
            content: content for which the signature

        Returns:
            Signature of the content signed with the private key.
        """
        return self.private_key.sign(content)

    # TODO: ATM only used for test cases - to be removed?
    def verify_signature(self, signature: str, data: bytes) -> None:
        """Verify one block of data was signed by the identiy.

        Args:
            signature: Signature to verify as Base64 encoded string.
            data: The data for which the signature

        Raises:
            InvalidSignature if the verification failed.
        """
        self.private_key.public_key().verify_signature(signature, data)


@dataclasses.dataclass(frozen=True)
class AssetType(BaseEntity):
    """Status of a previously submitted request."""

    asset_type_id: Identifier = dataclasses.field(default_factory=generate_id)
    scale: typing.Optional[int] = dataclasses.field(default=None, repr=False)
    _type: typing.ClassVar[typing.Dict[str, str]] = {
        "endorsements": "CreateAssetTypeEndorsementsRequest",
        "claims": "CreateAssetTypeClaimsRequest",
        "entity": "DefineAssetTypeRequest",
    }

    def __post_init__(self) -> None:
        """Assure the provided identifier is valid."""
        if invalid_chars.search(self.asset_type_id):
            raise ValueError(
                f"invalid identifier '{self.asset_type_id}' - "
                f"valid characters are {invalid_chars.pattern.replace('^', '')}"
            )

        object.__setattr__(self, "scale", _optional_positive_integer(self.scale))

    @property
    def id(self) -> Identifier:
        """Entity identifier."""
        return self.asset_type_id

    @property
    def type(self) -> str:
        """If the asset type is Quantifiable or Unique."""
        return "Quantifiable" if self.scale else "Unique"

    @property
    def resource(self) -> str:
        """Relative path where information about the asset type can be read."""
        return "/".join(("/api/v1/asset-types", self.asset_type_id))

    def _entity_specific_content(
        self,
        claims: typing.Optional[typing.List[bytes]] = None,
        endorser: typing.Optional["Identity"] = None,
        request_id: typing.Optional[Identifier] = None,
    ) -> ContentDict:
        if not claims and not endorser:
            d: ContentDict = {
                "assetTypeId": self.asset_type_id,
                "type": self.type,
            }
            if self.scale:
                d["scale"] = self.scale
            return d
        return {}


def _optional_positive_integer(
    value: typing.Optional[typing.Union[int, float, str]]
) -> typing.Optional[int]:
    if value is None:
        return value
    try:
        value_float = float(value)
        value_int = int(value_float)
        if value_int >= 0 and value_int == value_float:
            return value_int
    except ValueError:
        pass
    raise ValueError(f"must be a whole, positive number: '{value}'")


@dataclasses.dataclass(frozen=True)
class Asset(BaseEntity):
    """Status of a previously submitted request."""

    asset_type_id: Identifier
    asset_id: Identifier = dataclasses.field(default_factory=generate_id)
    # TODO: show quantity in repr only if it is present
    quantity: typing.Optional[str] = dataclasses.field(default=None, repr=False)
    _type: typing.ClassVar[typing.Dict[str, str]] = {
        "endorsements": "CreateAssetEndorsementsRequest",
        "claims": "CreateAssetClaimsRequest",
        "entity": "CreateAssetRequest",
    }

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
        quantity = _optional_positive_integer(self.quantity)
        if quantity is not None:
            object.__setattr__(self, "quantity", str(quantity))

    @property
    def id(self) -> Identifier:
        """Entity identifier."""
        return self.asset_id

    @property
    def resource(self) -> str:
        """Relative path where information about the asset can be read."""
        return "/".join(
            ("/api/v1/asset-types", self.asset_type_id, "assets", self.asset_id)
        )

    def _subject(self) -> typing.List[str]:
        return [self.asset_id, self.asset_type_id]

    def _entity_specific_content(
        self,
        claims: typing.Optional[typing.List[bytes]] = None,
        endorser: typing.Optional["Identity"] = None,
        request_id: typing.Optional[Identifier] = None,
    ) -> ContentDict:
        if claims:
            return {"subjectTypeId": self.asset_type_id}
        d: ContentDict = {
            "assetId": self.asset_id,
            "assetTypeId": self.asset_type_id,
        }
        if self.quantity is not None:
            d["quantity"] = self.quantity
        return d
