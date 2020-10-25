"""Client to access the iov42 platform."""
import json
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Type
from typing import Union

import httpx

from ._entity import Asset
from ._entity import AssetType
from ._entity import Identity
from ._entity import Operation
from ._entity import Request
from ._entity import Response
from ._exceptions import AssetAlreadyExists
from ._exceptions import DuplicateRequestId


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

    def put(
        self,
        entity: Union[Type[Identity], Identity, AssetType, Asset],
        *,
        request_id: str = "",
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
        entity_object: Union[Identity, AssetType, Asset] = (
            self.identity if entity == Identity else entity  # type: ignore[assignment]
        )
        endorser = self.identity if endorse else None
        request = Request(
            Operation.WRITE,
            entity_object,
            id=request_id,
            claims=claims,
            endorser=endorser,
        )
        return self.__send_request(request)

    def __send_request(self, request: Request) -> Response:
        request.add_authentication_header(self.identity)

        # TODO: at the moment we do not take care of the correct points
        response = self.client.put(
            "/api/v1/requests/" + request.id,
            content=request.content,
            headers=request.headers,
        )
        # import pdb

        # pdb.set_trace()

        # If we reach this point we got a response

        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 400:
                # TODO provide entity instead of the id
                raise AssetAlreadyExists(
                    f"identity '{self.identity.identity_id}' already exists",
                    id=self.identity.identity_id,
                    request_id=request.id,
                ) from e
            else:
                # TODO we have to provide a fallback for unknown errors
                raise DuplicateRequestId(
                    "request ID already exists", request_id=request.id
                )

        return _deserialize_response(response.content)


def _deserialize_response(content: bytes) -> Response:
    def _request_decoder(obj: Dict[str, Any]) -> Response:
        return Response(
            request_id=obj["requestId"],
            proof=obj["proof"],
            resources=obj["resources"],
        )

    return json.loads(content, object_hook=_request_decoder)  # type: ignore
