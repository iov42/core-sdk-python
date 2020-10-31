"""Request send to the iov42 platform."""
import json
import typing

from ._crypto import iov42_encode
from ._entity import assure_valid_identifier
from ._entity import Entity
from ._entity import hashed_claim
from ._entity import Identifier
from ._entity import PrivateIdentity
from ._models import Claims
from ._models import Iov42Header
from ._models import Signature


class Request:
    """An HTTP request tailored to be used for iov42 platforms."""

    def __init__(  # noqa: C901
        self,
        method: str,
        url: str,
        entity: Entity,
        *,
        claims: typing.Optional[Claims] = None,
        endorser: typing.Optional[typing.Union[PrivateIdentity, Identifier]] = None,
        create_claims: bool = False,
        content: typing.Optional[typing.Union[str, bytes]] = None,
        authorisations: typing.Optional[typing.List[Signature]] = None,
        request_id: Identifier = "",
        node_id: Identifier = "",
    ) -> None:
        """Creates request object.

        Args:
            method: HTTP method for the new Request object: `PUT` or `GET`.
            url: URL for the new Request object.
            entity: entity upon which the operation is perfomed.
            claims: List of claims to be created and/or endorsed.
            endorser: If True create endorsements of the given claims.
            create_claims: create claims with the endorsements at once.
            content: Content for PUT request if provided (endorsement).
            authorisations: Authorisations for the provided content.
            request_id: The identifier of the request. If not provided one is generated.
            node_id: The identifier of the node needed for GET requests. It can
                     be obtained by the `/node-info` endpoint.

        Raises:
            TypeError: if claims are missing when an endorser is provided.

            ValueError: if request_id contains invalid characters.
        """
        if endorser and not claims:
            raise TypeError(
                "missing required keyword argument needed for endorsement: 'claims'"
            )
        if method == "GET" and not node_id:
            raise TypeError("missing required keyword argument: 'node_id'")
        self.method = method
        self.url = url.rstrip("/")
        self.entity = entity
        self.headers: typing.Dict[str, str] = {}
        if content:
            content_str = content if isinstance(content, str) else content.decode()
            self.request_id = json.loads(content_str)["requestId"]
            self._content = content if isinstance(content, bytes) else content.encode()
            # TODO: raise error if a request_id and content is provided
        else:
            self.request_id = assure_valid_identifier(request_id)
        if endorser is not None:
            self.endorser = endorser
        if claims is not None:
            self.claims = claims

        if method == "PUT":
            self.resource = "/api/v1/requests/" + self.request_id
            self.url = self.url + self.resource
            self.headers["content-type"] = "application/json"
            if claims:
                claims_header = (
                    {hashed_claim(c): c.decode() for c in self.claims}
                    if (not endorser and not content) or create_claims
                    else {}
                )
                self.__add_header("x-iov42-claims", claims_header)
            self.authorisations: typing.List[Signature] = (
                authorisations if authorisations else []
            )
        elif method == "GET":
            path = self.entity.resource.split("/")
            self._query_string = "?requestId=" + self.request_id + "&nodeId=" + node_id
            if claims:
                # TODO: retrieve claim information - we use only the 1st
                # element. Raise exception if more than one is provided.
                path = path + ["claims", hashed_claim(self.claims[0])]
                if endorser:
                    path = path + [
                        "endorsements",
                        typing.cast(Identifier, self.endorser),
                    ]
            self.resource = "/".join(path)
            self.url = self.url + self.resource + self._query_string

    @property
    def content(self) -> bytes:
        """Request content."""
        if not hasattr(self, "_content"):
            if self.method == "PUT":
                endorser = (
                    typing.cast(PrivateIdentity, self.endorser)
                    if hasattr(self, "endorser")
                    else None
                )
                claims = self.claims if hasattr(self, "claims") else None
                self._content = self.entity.put_request_content(
                    claims=claims,
                    endorser=endorser,
                    request_id=self.request_id,
                )
            else:
                self._content = b""
        return self._content

    @staticmethod
    def create_signature(identity: PrivateIdentity, data: bytes) -> Signature:
        """Returns signature of data signed by the identity."""
        return {
            "identityId": identity.identity_id,
            "protocolId": identity.private_key.protocol.name,
            "signature": identity.sign(data),
        }

    def add_authentication_header(self, identity: PrivateIdentity) -> None:
        """Create authenication headear and (if needed) authorsiation header."""
        if self.method == "PUT":
            self.__authorised_by(identity)
            self.__add_header("x-iov42-authorisations", self.authorisations)
            data = ";".join(
                [auth["signature"] for auth in self.authorisations]
            ).encode()
        elif self.method == "GET":
            data = (self.resource + self._query_string).encode()
        else:
            # Unknown method, don't do anything.
            return
        authentication = self.create_signature(identity, data)
        self.__add_header("x-iov42-authentication", authentication)

    # TODO: do we really need this - only used by tests
    def __authorised_by(self, identity: PrivateIdentity) -> None:
        """Add authorisation by signing the request content."""
        if identity.identity_id in [a["identityId"] for a in self.authorisations]:
            return
        authorisation = self.create_signature(identity, self.content)
        self.authorisations.append(authorisation)

    def __add_header(self, header: str, data: Iov42Header) -> None:
        self.headers[header] = iov42_encode(json.dumps(data)).decode()
