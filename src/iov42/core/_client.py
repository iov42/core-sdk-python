"""Client to access the io42 platform."""
import typing
from types import TracebackType

from ._entity import Entity
from ._entity import Identifier
from ._entity import Identity
from ._httpclient import DEFAULT_TIMEOUT_CONFIG
from ._httpclient import HttpClient
from ._httpclient import TimeoutTypes
from ._httpclient import UNSET
from ._httpclient import UnsetType
from ._models import Authorisations
from ._models import Claims
from ._request import Request
from ._response import Response

T = typing.TypeVar("T", bound="Client")


class Client:
    """Entrypoint to access the iov42 platform."""

    def __init__(
        self,
        base_url: str,
        identity: Identity,
        *,
        timeout: TimeoutTypes = DEFAULT_TIMEOUT_CONFIG,
    ):
        """Create client to access the iov42 platform.

        Args:
            base_url: A URL where the iov42 service is available.
            identity: The identity used to authenticate against the platform.
            timeout: The timeout configuration to use when sending requests.
        """
        self.identity = identity
        self._client = HttpClient(base_url=base_url, timeout=timeout)

    @property
    def node_id(self) -> Identifier:
        """Identifier of the node from which data is read."""
        if not hasattr(self, "_node_id"):
            response = self._client.get("/api/v1/node-info")
            response.raise_for_status()
            self._node_id = typing.cast(Identifier, response.json()["nodeId"])
        return self._node_id

    def close(self) -> None:
        """Release all resources."""
        self._client.close()

    def build_request(
        self,
        method: str,
        *,
        entity: Entity,
        request_id: Identifier = "",
        claims: typing.Optional[Claims] = None,
        endorser: typing.Optional[typing.Union[Identity, Identifier]] = None,
        create_claims: bool = False,
        content: typing.Optional[typing.Union[str, bytes]] = None,
        authorisations: typing.Optional[Authorisations] = None,
        node_id: Identifier = "",
    ) -> Request:
        """Build and return a request instance.

        Args:
            method: HTTP method for the new Request object: `PUT` or `GET`.
            entity: the entity to be created on the platform.
            request_id: platform request id. If not provided it will be generated.
            claims: if provided, create the entity claims.
            endorser: if provided create endorsements of the given claims.
            create_claims: create claims with the endorsements at once.
            content: Content of a PUT request.
            authorisations: Authorisations of a PUT request.
            node_id: the identifier of the node needed for GET requests. It can
                 be obtained by the `/node-info` endpoint.

        Returns:
            Newly created request object.
        """
        request = Request(
            method,
            self._client.base_url,
            entity=entity,
            claims=claims,
            endorser=endorser,
            create_claims=create_claims,
            content=content,
            authorisations=authorisations,
            request_id=request_id,
            node_id=node_id,
        )
        # TODO: do we really want to do that here? It makes more sense to do it
        # when ding the request.
        return request

    def put(
        self,
        entity: Entity,
        *,
        claims: typing.Optional[Claims] = None,
        endorse: bool = False,
        create_claims: bool = False,
        content: typing.Optional[typing.Union[str, bytes]] = None,
        authorisations: typing.Optional[Authorisations] = None,
        request_id: Identifier = "",
        timeout: typing.Union[TimeoutTypes, UnsetType] = UNSET,
    ) -> Response:
        """Creates a new entity on the platform.

        Args:
            entity: the entity to be created on the platform.
            claims: if provided, create the entity claims.
            endorse: create the endorsements to the provided claims.
            create_claims: create claims with the endorsements at once.
            content: provide existing PUT content. This may be used to send 3rd party endorsements.
            authorisations: needed authorisations to the PUT content.
            request_id: Unique identifier associated with the request. If not provided it will be generated.
            timeout: The timeout configuration for this GET request.

        Returns:
            Response to the request to create the entity.
        """
        endorser = self.identity if endorse else None
        request = self.build_request(
            "PUT",
            entity=entity,
            claims=claims,
            endorser=endorser,
            create_claims=create_claims,
            content=content,
            authorisations=authorisations,
            request_id=request_id,
        )
        return self.send(request)

    def get(
        self,
        entity: Entity,
        *,
        request_id: Identifier = "",
        claim: typing.Optional[bytes] = None,
        endorser_id: typing.Optional[Identifier] = None,
        timeout: typing.Union[TimeoutTypes, UnsetType] = UNSET,
    ) -> Response:
        """Create a request to read information from the platform.

        Args:
            entity: the entity to be created on the platform.
            request_id: platform request id. If not provided it will be generated.
            claim: # TODO TBD
            endorser_id: # TODO TBD
            timeout: The timeout configuration for this PUT request.

        Returns:
            Response to the request to create the entity.

        Raises:
            AssetAlreadyExists if the entity already exists.
            DuplicateRequestId if 'request_id' was already used.
        """
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

    def send(
        self,
        request: Request,
        *,
        timeout: typing.Union[TimeoutTypes, UnsetType] = UNSET,
    ) -> Response:
        """Send a request.

        Typically you'll want to build one with Client.build_request() so that
        any client-level configuration is merged into the request, but passing
        an explicit iov42.core.Request() is supported as well.

        Args:
            request: the request to send.
            timeout: The timeout configuration for this request.

        Returns:
            Response to the request sent.
        """
        request.add_authentication_header(self.identity)
        response = self._client.send(request)
        return response

    def __enter__(self: T) -> T:
        """Provides a context manager to cleanup used resources."""
        return self

    def __exit__(
        self,
        exc_type: typing.Optional[typing.Type[BaseException]] = None,
        exc_value: typing.Optional[BaseException] = None,
        traceback: typing.Optional[TracebackType] = None,
    ) -> None:
        """Release all resources."""
        self._client.close()

    def __del__(self) -> None:
        """Release all resources."""
        self._client.close()
