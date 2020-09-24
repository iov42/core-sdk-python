"""Client to access the iov42 platform."""
import base64
import json
import re
import uuid
from dataclasses import dataclass
from typing import Any
from typing import Dict
from typing import List

import httpx

from ._crypto import PrivateKey
from ._exceptions import AssetAlreadyExists
from ._exceptions import DuplicateRequestId


@dataclass
class Request:
    """Status of a previously submitted request."""

    request_id: str
    proof: str
    resources: List[str]


# TODO: we do not accept '/' as a valid character, the platform does.
_invalid_chars = re.compile(r"[^a-zA-Z0-9._\-+]")


@dataclass(frozen=True)
class Identity:
    """Identity used to sign the requests."""

    private_key: PrivateKey
    identity_id: str = str(uuid.uuid4())

    def sign(self, content: str) -> str:
        """Signs content with private key.

        Args:
            content: content for which the signature

        Returns:
            Signature of the content signed with the private key.
        """
        return self.private_key.sign(content)

    def __post_init__(self) -> None:
        """Raise ValueError if 'address' contains invalid characters.

        Raises:
            TypeError: if no private key is provided
            ValueError: if the given address contains invalid characters.
        """
        if not isinstance(self.private_key, PrivateKey):
            raise TypeError(
                f"must be PrivateKey, not {type(self.private_key).__name__}"
            )
        if _invalid_chars.search(self.identity_id):
            # TODO: provide the list of valid characters from the regexp
            raise ValueError(
                f"invalid identifier '{self.identity_id}' - valid characters are [a-zA-Z0-9_.-+]"
            )


class Client:
    """Entrypoint to access the iov42 platform."""

    # TODO: provide a default_request_id_generator
    def __init__(self, url: str, identity: Identity):
        """Create client to access the iov42 platform.

        Args:
            url: URL endpoint to access the iov42 platform.
            identity: used to authenticate against the platform.
        """
        # TODO this will leak connections if they are not closed. We should
        # provide a context manager for this class.
        self.client = httpx.Client(base_url=url)
        self.identity = identity

    def create_identity(self, request_id: str = "") -> Request:
        """Returns a new identity issued by the platform.

        Args:
            request_id: platform request id. If not provided will ge generated.

        Returns:
            The newly created identity.

        Raises:
            AssetAlreadyExists: If the identity already exists.
            DuplicateRequestId: If 'request_id' was already used.
        """
        if not request_id:
            request_id = str(uuid.uuid4())
        assert_valid_address(request_id)

        # TODO fix the deep access of properties
        content = json.dumps(
            {
                "_type": "IssueIdentityRequest",
                "identityId": self.identity.identity_id,
                "publicCredentials": {
                    "key": self.identity.private_key.public_key().dump(),
                    "protocolId": self.identity.private_key.protocol.name,
                },
                "requestId": request_id,
            },
            separators=(",", ":"),
        )

        signatures = []
        signatures.append(generate_signature(self.identity, content))

        headers = {
            "Content-Type": "application/json",
            "X-IOV42-Authentication": create_authentication_header(
                self.identity, signatures
            ),
            "X-IOV42-Authorisations": create_authorisations_header(signatures),
        }

        # Request errors are raised toot-sweet
        response = self.client.put(
            "/api/v1/requests/" + request_id, content=content, headers=headers
        )

        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 400:
                # TODO provide entity instead of the id
                raise AssetAlreadyExists(
                    f"identity '{self.identity.identity_id}' already exists",
                    id=self.identity.identity_id,
                    request_id=request_id,
                ) from e
            else:
                # TODO we have to provide a fallback for unknown errors
                raise DuplicateRequestId(
                    "request ID already exists", request_id=request_id
                )

        return _deserialize_response(response.content)


def assert_valid_address(address: str) -> None:
    """Raise ValueError if 'address' contains invalid characters.

    Args:
        address: the address which is checked for validity.

    Raises:
        ValueError: if the given address contains invalid characters.
    """
    if _invalid_chars.search(address):
        raise ValueError(
            f"invalid address '{address}' - valid characters are [a-zA-Z0-9_.-+/]"
        )


def _deserialize_response(content: bytes) -> Request:
    def _request_decoder(obj: Dict[str, Any]) -> Request:
        return Request(
            request_id=obj["requestId"],
            proof=obj["proof"],
            resources=obj["resources"],
        )

    return json.loads(content, object_hook=_request_decoder)  # type: ignore


def generate_signature(identity: Identity, content: str) -> Dict[str, str]:
    """Returns signature used by the x-iov42-Authorisations header."""
    return {
        "identityId": identity.identity_id,
        "protocolId": identity.private_key.protocol.name,
        "signature": identity.sign(content),
    }


def create_authorisations_header(signatures: List[Dict[str, str]]) -> str:
    """Returns content of x-iov42-Authorisations header with provided signatures."""
    return _str_encode(json.dumps(signatures))


def create_authentication_header(
    identity: Identity, signatures: List[Dict[str, str]]
) -> str:
    """Returns content of x-iov42-Authentication header."""
    data = ";".join([s["signature"] for s in signatures])
    return _str_encode(
        json.dumps(
            {
                "identityId": identity.identity_id,
                "protocolId": identity.private_key.protocol.name,
                "signature": identity.sign(data),
            }
        )
    )


def _str_encode(data: str) -> str:
    """Standard encoding for data strings."""
    return base64.urlsafe_b64encode(data.encode()).decode()
