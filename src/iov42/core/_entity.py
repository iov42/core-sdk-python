"""Entities of the iov42 platform."""
import base64
import json
import re
import uuid
from enum import Enum
from typing import Dict
from typing import List
from typing import Optional
from typing import Union

from ._crypto import PrivateKey

# TODO: can we convert this to data classes?


class Operation(Enum):
    """Operations perfomed on the platform."""

    READ = "READ"
    WRITE = "WRITE"


class Entity:
    """Base class for addressable entities on the iov42 platform."""

    # TODO: we do not accept '/' as a valid character, the platform does.
    _invalid_chars = re.compile(r"[^a-zA-Z0-9._\-+]")

    def __init__(self, id: str = "") -> None:
        """Create addressable entity on the iov42 platform.

        Args:
            id: entity identifier

        Raises:
            ValueError: if the given address contains invalid characters.
        """
        if self._invalid_chars.search(id):
            raise ValueError(
                f"invalid identifier '{id}' - "
                f"valid characters are {self._invalid_chars.pattern.replace('^', '')}"
            )
        self.id = str(uuid.uuid4()) if not id else id

    def __str__(self) -> str:
        """Returns informal representation of an entity."""
        return str(self.id)

    def __repr__(self) -> str:
        """Returns printable representation of an entity."""
        return f"{self.__class__.__name__}(id={self.id})"

    def request_content(self, operation: Operation, request_id: str) -> str:
        """Returns request content of the entity based on the operation to perform."""
        ...  # pragma: no cover


class Identity(Entity):
    """Identity used to sign the requests."""

    def __init__(self, private_key: PrivateKey, id: str = "") -> None:
        """Create new identity.

        Args:
            private_key: the identiy private key used for authentication.
            id: the identifier of the identity.

        Raises:
            TypeError: if the povided key is not a PrivateKey.

            ValueError: if id contains invalid characters.
        """
        super().__init__(id)
        if not isinstance(private_key, PrivateKey):
            raise TypeError(f"must be PrivateKey, not {type(private_key).__name__}")
        self.private_key = private_key

    @property
    def identity_id(self) -> str:
        """Returns the idenfier."""
        # TODO: kept for backwards compatiblity - remove this.
        return self.id

    def sign(self, content: str) -> str:
        """Signs content with private key.

        Args:
            content: content for which the signature

        Returns:
            Signature of the content signed with the private key.
        """
        return self.private_key.sign(content)

    def verify_signature(self, signature: str, data: str) -> None:
        """Verify one block of data was signed by the identiy.

        Args:
            signature: Signature to verify as Base64 encoded string.
            data: The data for which the signature

        Raises:
            InvalidSignature if the verification failed.
        """
        self.private_key.public_key().verify_signature(signature, data)

    def request_content(self, operation: Operation, request_id: str) -> str:
        """Create request content."""
        return json.dumps(
            {
                "_type": "IssueIdentityRequest",
                "identityId": self.identity_id,
                "publicCredentials": {
                    "key": self.private_key.public_key().dump(),
                    "protocolId": self.private_key.protocol.name,
                },
                "requestId": request_id,
            },
            separators=(",", ":"),
        )


class AssetType(Entity):
    """Status of a previously submitted request."""

    def __init__(self, id: str = "", scale: Optional[int] = None) -> None:
        """Creates an asset type.

        Args:
            scale: whether instance of this asset type are entities or quantities.
            id: the identifier of the asset type.

        Raises:
            ValueError if the given id contains invalid characters.
        """
        super().__init__(id)
        self.type = "Quantifiable" if scale else "Unique"

    def __repr__(self) -> str:
        """Returns printable representation of an entity."""
        return f"{self.__class__.__name__}(id={self.id},type={self.type})"

    def request_content(self, operation: Operation, request_id: str) -> str:
        """Create request content."""
        content = json.dumps(
            {
                "_type": "DefineAssetTypeRequest",
                "assetTypeId": self.id,
                "type": self.type,
                "requestId": request_id,
            }
        )
        return content


class Asset(Entity):
    """Status of a previously submitted request."""

    def __init__(self, asset_type: Union[str, AssetType], id: str = "") -> None:
        """Creates an asset.

        Args:
            asset_type: the asset type of which the new asset will belong.
            id: the identifier of the asset.

        Raises:
            ValueError if the given id or asset_type contains invalid characters.
        """
        super().__init__(id)
        self.asset_type = (
            asset_type if isinstance(asset_type, AssetType) else AssetType(asset_type)
        )

    def request_content(self, operation: Operation, request_id: str) -> str:
        """Create request content."""
        content = json.dumps(
            {
                "_type": "CreateAssetRequest",
                "assetId": self.id,
                "assetTypeId": self.asset_type.id,
                "requestId": request_id,
            }
        )
        return content


class Request(Entity):
    """Status of a previously submitted request."""

    def __init__(self, operation: Operation, entity: Entity, *, id: str = "") -> None:
        """Creates request response.

        Args:
            operation: "PUT", "GET"
            id: the identifier of the request. If not provided one is generated.
            entity: entity upton which the operation is perfomed.

        Raises:
            ValueError if the given id contains invalid characters.
        """
        super().__init__(id)
        self.operation = operation
        self.entity = entity
        self.authorisations: List[Dict[str, str]] = []
        self.headers = {
            "Content-Type": "application/json",
        }

    @property
    def content(self) -> str:
        """Content for the request."""
        if "content" not in self.__dict__:
            self.__dict__["content"] = (
                self.entity.request_content(self.operation, self.id)
                if self.entity
                else ""
            )
        return self.__dict__["content"]  # type: ignore[no-any-return]

    def add_authentication_header(self, identity: Identity) -> None:
        """Creates authorisation and authenication headears."""
        self.__authorise(identity)
        self.__add_authorisations_header()
        self.__add_authentication_header(identity)

    def __authorise(self, identity: Identity) -> None:
        """Adds authorisation of the identity."""
        authorisation = self.__create_signature(identity, self.content)
        # TODO make sure we can not add the same authoirsation twice
        self.authorisations.append(authorisation)

    def __create_signature(self, identity: Identity, data: str) -> Dict[str, str]:
        return {
            "identityId": identity.identity_id,
            "protocolId": identity.private_key.protocol.name,
            "signature": identity.sign(data),
        }

    def __add_authorisations_header(self) -> None:
        self.__add_header("X-IOV42-Authorisations", self.authorisations)

    def __add_authentication_header(self, identity: Identity) -> None:
        data = ";".join([auth["signature"] for auth in self.authorisations])
        authentication = self.__create_signature(identity, data)
        self.__add_header("X-IOV42-Authentication", authentication)

    def __add_header(
        self, key: str, data: Union[Dict[str, str], List[Dict[str, str]]]
    ) -> None:
        self.headers[key] = base64.urlsafe_b64encode(json.dumps(data).encode()).decode()


class Response:
    """Response of a previously submitted request."""

    def __init__(
        self, request_id: str, proof: str, resources: Optional[List[str]]
    ) -> None:
        """Creates request response.

        Args:
            request_id: the identifier of the request
            proof: the location of the generated proof to the request.
            resources: the location of the affected resources.
        """
        self.request_id = request_id
        self.proof = proof
        self.resources = resources if resources else []

    def __str__(self) -> str:
        """Returns printable representation of an entity."""
        return f"{self.__class__.__name__}(request_id={self.request_id})"

    def __repr__(self) -> str:
        """Returns printable representation of an entity."""
        return (
            f"{self.__class__.__name__}(request_id={self.request_id},proof={repr(self.proof)},"
            f"resources={repr(self.resources)})"
        )
