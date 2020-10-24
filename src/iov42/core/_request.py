"""Request send to the iov42 platform."""
import json
from typing import cast
from typing import Dict
from typing import List
from typing import Optional
from typing import Union

from ._crypto import iov42_encode
from ._entity import assure_valid_identifier
from ._entity import Claim
from ._entity import Identifier
from ._entity import Identity
from ._models import Entity
from ._models import Iov42Header


class Request:
    """An HTTP request tailored to be used for iov42 platforms."""

    def __init__(
        self,
        method: str,
        url: str,
        entity: Entity,
        *,
        request_id: Identifier = "",
        claims: Optional[List[bytes]] = None,
        endorser: Optional[Union[Identity, Identifier]] = None,
        node_id: Identifier = "",
    ) -> None:
        """Creates request object.

        Args:
            method: HTTP method for the new Request object: `PUT` or `GET`.
            url: URL for the new Request object.
            entity: entity upon which the operation is perfomed.
            request_id: the identifier of the request. If not provided one is generated.
            claims: list of claims to be created and/or endorsed.
            endorser: if provided create endorsements of the given claims.
            node_id: the identifier of the node needed for GET requests. It can
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
        self.request_id = assure_valid_identifier(request_id)
        self.entity = entity
        self.headers: Dict[str, str] = {}
        if endorser:
            self.endorser = endorser
        if claims:
            self.claims = [Claim(c) for c in claims]

        if method == "PUT":
            self.resource = "/api/v1/requests/" + self.request_id
            self.url = self.url + self.resource
            self.headers["content-type"] = "application/json"
            if claims:
                self.__add_header(
                    "x-iov42-claims", {c.hash: c.data.decode() for c in self.claims}
                )
            self.authorisations: List[Dict[str, str]] = []
        elif method == "GET":
            path = self.entity.resource.split("/")
            self._query_string = "?requestId=" + self.request_id + "&nodeId=" + node_id
            if claims:
                # TODO: retrieve claim information - we use only the 1st
                # element. Raise exception if more than one is provided.
                path = path + ["claims", self.claims[0].hash]
                if endorser:
                    path = path + ["endorsements", cast(Identifier, self.endorser)]
            self.resource = "/".join(path)
            self.url = self.url + self.resource + self._query_string

    @property
    def content(self) -> bytes:
        """Request content."""
        if not hasattr(self, "_content"):
            self._content = (
                self.entity.request_content(self).encode()
                if self.entity and self.method == "PUT"
                else b""
            )
        return self._content

    def add_authentication_header(self, identity: Identity) -> None:
        """Create authenication headear and (if needed) authorsiation header."""
        if self.method == "PUT":
            authorisation = self.__create_signature(identity, self.content)
            self.__add_authorsation(authorisation)
            self.__add_header("x-iov42-authorisations", self.authorisations)
            data = ";".join(
                [auth["signature"] for auth in self.authorisations]
            ).encode()
        elif self.method == "GET":
            data = (self.resource + self._query_string).encode()
        else:
            # TODO: should we raise something here?
            return
        authentication = self.__create_signature(identity, data)
        self.__add_header("x-iov42-authentication", authentication)

    def __create_signature(self, identity: Identity, data: bytes) -> Dict[str, str]:
        return {
            "identityId": identity.identity_id,
            "protocolId": identity.private_key.protocol.name,
            "signature": identity.sign(data),
        }

    def __add_authorsation(self, authorisation: Dict[str, str]) -> None:
        """Adds authorisation of the identity."""
        # TODO make sure we can not add the same authorisation twice
        self.authorisations.append(authorisation)

    def __add_header(self, header: str, data: Iov42Header) -> None:
        self.headers[header] = iov42_encode(json.dumps(data)).decode()
