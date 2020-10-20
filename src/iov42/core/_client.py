"""Client to access the io42 platform."""
import json
import re
from typing import cast
from typing import Dict
from typing import List
from typing import Optional
from typing import Sequence
from typing import Union

import httpx

from ._crypto import iov42_encode
from ._entity import assure_valid_identifier
from ._entity import Claim
from ._entity import Identifier
from ._entity import Identity
from ._exceptions import AssetAlreadyExists
from ._exceptions import DuplicateRequestId
from ._models import Entity
from ._models import Iov42Header
from ._models import URL
from ._models import URLTypes


class Request:
    """An HTTP request tailored to be used for iov42 platforms."""

    def __init__(
        self,
        method: str,
        url: URLTypes,
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
        # If we do not have a trailing "/", url.join() will remove the in the url.
        self.url = self._enforce_trailing_slash(URL(url))
        self.request_id = assure_valid_identifier(request_id)
        self.entity = entity
        self.endorser = endorser
        self.headers: Dict[str, str] = {}
        self.claims: List[Claim] = [Claim(c) for c in claims] if claims else []

        if method == "PUT":
            self.resource = URL("/api/v1/requests/" + self.request_id)
            # Assure we strip the leading '/', otherwise a any path in the URL
            # is stripped and the host part remains.
            self.url = self.url.join(
                self.resource.copy_with(path=self.resource.path.lstrip("/"))
            )
            self.headers["content-type"] = "application/json"
            if claims:
                self.__add_header(
                    "x-iov42-claims", {c.hash: c.data.decode() for c in self.claims}
                )
        elif method == "GET":
            path = self.entity.resource.split("/")
            if claims:
                # TODO: retrieve claim information - we use only the 1st
                # element. Raise exception if more than one is provided.
                path = path + ["claims", self.claims[0].hash]
                if endorser:
                    path = path + ["endorsements", cast(Identifier, self.endorser)]
            self.resource = URL("/".join(path))
            # Assure we strip the leading '/', otherwise a any path in the URL
            # is stripped and the host part remains.
            self.url = self.url.join(
                self.resource.copy_with(path=self.resource.path.lstrip("/"))
            )
            # URL.join() removes query parameter
            self.url = URL(
                self.url, params={"requestId": self.request_id, "nodeId": node_id}
            )
        self.authorisations: List[Dict[str, str]] = []

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

    def _enforce_trailing_slash(self, url: URL) -> URL:
        if url.path.endswith("/"):
            return url
        return url.copy_with(path=url.path + "/")

    def _build_request(self) -> httpx.Request:
        """Build a request instance which the client can send."""
        request = httpx.Request(
            self.method, self.url, headers=self.headers, content=self.content
        )
        return request

    def add_authentication_header(self, identity: Identity) -> None:
        """Create authenication headear and (if needed) authorsiation header."""
        if self.method == "PUT":
            authorisation = self.__create_signature(identity, self.content)
            self.__add_authorsation(authorisation)
            self.__add_header("x-iov42-authorisations", self.authorisations)
            data = ";".join(
                [auth["signature"] for auth in self.authorisations]
            ).encode()
        else:
            data = self.url.raw_path
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


class Response:
    """Response provided from the iov42 platform.

    The class provide a comfortable way to access JSON representation with
    instance variables. Keys are converted form CamelCase to snake_case.

    Note: any changes in the reponse will be forwarded to the client.
    """

    pattern = re.compile(r"(?<!^)(?=[A-Z])")

    @classmethod
    def _camel_to_snake(cls, name: str) -> str:
        return cls.pattern.sub("_", name).lower()

    def __init__(self, d: Union[Dict[str, str], Dict[str, Sequence[Dict[str, str]]]]):
        """Provide access to dictionarry keys as attribute."""
        self.__dict__.update({self._camel_to_snake(k): v for k, v in d.items()})
        for k, v in d.items():
            k = self._camel_to_snake(k)
            if isinstance(v, dict):  # type: ignore[unreachable]
                self.__dict__[k] = Response(v)  # pragma: no cover
            elif isinstance(v, list):
                # TODO: replace this with a list comprehension.
                list_element = []
                for e in v:
                    list_element.append(Response(e) if isinstance(e, dict) else e)
                self.__dict__[k] = list_element


class Client:
    """Entrypoint to access the iov42 platform."""

    # TODO: provide means to set a default_request_id_generator
    # TODO: provide means to set time out parameters
    def __init__(self, base_url: str, identity: Identity):
        """Create client to access the iov42 platform.

        Args:
            base_url: base URL where the iov42 service is available.
            identity: used to authenticate against the platform.
        """
        # TODO this will leak connections if they are not closed. We should
        # provide a context manager for this class.
        self.client = httpx.Client(base_url=base_url)
        self.identity = identity

    @property
    def node_id(self) -> Identifier:
        """Identifier of the node from which data is read."""
        if not hasattr(self, "_node_id"):
            response = self.client.get("/api/v1/node-info")
            response.raise_for_status()
            self._node_id = cast(Identifier, response.json()["nodeId"])
        return self._node_id

    def build_request(
        self,
        method: str,
        *,
        entity: Entity,
        url: URLTypes = "",
        request_id: Identifier = "",
        claims: Optional[List[bytes]] = None,
        endorser: Optional[Union[Identity, Identifier]] = None,
        node_id: Identifier = "",
    ) -> Request:
        """Build and return a request instance.

        The `url` argument is merged with any `base_url` set on the client.
        The request is authorised and signed by the clients identiy.

        Args:
            method: HTTP method for the new Request object: `PUT` or `GET`.
            url: URL for the new Request object.
            entity: the entity to be created on the platform.
            request_id: platform request id. If not provided it will be generated.
            claims: if provided, create the entity claims.
            endorser: if provided create endorsements of the given claims.
            node_id: the identifier of the node needed for GET requests. It can
                     be obtained by the `/node-info` endpoint.

        Returns:
            Newly created request object.
        """
        url = self.client._merge_url(url)
        request = Request(
            method,
            url,
            entity=entity,
            request_id=request_id,
            claims=claims,
            endorser=endorser,
            node_id=node_id,
        )
        request.add_authentication_header(self.identity)
        return request

    def put(
        self,
        entity: Entity,
        *,
        request_id: Identifier = "",
        claims: Optional[List[bytes]] = None,
        endorse: bool = False,
    ) -> Response:
        """Creates a new entity on the platform.

        Args:
            entity: the entity to be created on the platform.
            request_id: platform request id. If not provided it will be generated.
            claims: if provided, create the entity claims.
            endorse: if True, create the endorsements to the provided claim.

        Returns:
            Response to the request to create the entity.

        Raises:
            AssetAlreadyExists if the entity already exists.

            DuplicateRequestId if 'request_id' was already used.
        """
        request_id = assure_valid_identifier(request_id)
        endorser = self.identity if endorse else None
        request = self.build_request(
            "PUT",
            entity=entity,
            request_id=request_id,
            claims=claims,
            endorser=endorser,
        )
        return self.send(request)

    def get(
        self,
        entity: Entity,
        *,
        request_id: Identifier = "",
        claim: Optional[bytes] = None,
        endorser_id: Optional[Identifier] = None,
    ) -> Response:  # pragma: no cover
        """Create a request to read information from the platform.

        Args:
            entity: the entity to be created on the platform.
            request_id: platform request id. If not provided it will be generated.
            claim: # TODO TBD
            endorser_id: # TODO TBD

        Returns:
            Response to the request to create the entity.

        Raises:
            AssetAlreadyExists if the entity already exists.
            DuplicateRequestId if 'request_id' was already used.
        """
        request_id = assure_valid_identifier(request_id)
        claims = [claim] if claim else None
        request = self.build_request(
            "GET",
            entity=entity,
            request_id=request_id,
            claims=claims,
            endorser=endorser_id,
            node_id=self.node_id,
        )
        return self.send(request)

    def send(self, request: Request) -> Response:
        """Send a request.

        Typically you'll want to build one with Client.build_request() so that
        any client-level configuration is merged into the request, but passing
        an explicit iov42.core.Request() is supported as well.

        Args:
            request: the request to send.

        Returns:
            Response to the request sent.

        Raises:
            AssetAlreadyExists: if the entity already exists.
            DuplicateRequestId: if 'request_id' was already used.
        """
        client_specific_request = request._build_request()
        response = self.client.send(client_specific_request)

        # If we reach this point we got a response

        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 400:
                # TODO provide entity instead of the id
                raise AssetAlreadyExists(
                    f"identity '{self.identity.identity_id}' already exists",
                    id=self.identity.identity_id,
                    request_id=request.request_id,
                ) from e
            else:
                # TODO we have to provide a fallback for unknown errors
                raise DuplicateRequestId(
                    "request ID already exists", request_id=request.request_id
                ) from e

        return Response(json.loads(response.content))
