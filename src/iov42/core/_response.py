"""Responses provided by the iov42 platform."""
import json
from dataclasses import dataclass
from typing import List
from typing import Union

from ._entity import Identifier
from ._request import Request


@dataclass(frozen=True)
class BaseResponse:
    """Base class for successful platform responses."""

    request: Request
    # TODO: what information are we going to provide form the HTTP response.
    # Note: we do not want to leak out the HTTP response itself.
    content: bytes


@dataclass(frozen=True)
class EntityCreated(BaseResponse):
    """Entity was successfully created."""

    proof: str
    resources: List[str]


@dataclass(frozen=True)
class Endorsement(BaseResponse):
    """Endorsement against a subject claim of the given endorser exists."""

    proof: str
    endorser_id: Identifier
    endorsement: str


Response = Union[EntityCreated, Endorsement]


def deserialize(request: Request, content: bytes) -> Response:
    """Deserializes the HTTP response content to a Response."""
    content_json = json.loads(content.decode())
    if request.method == "PUT":
        return EntityCreated(
            request,
            content,
            content_json["proof"],
            resources=content_json["resources"],
        )
    else:
        if "/endorsements/" in request.resource:  # pragma: no cover
            return Endorsement(
                request,
                content,
                content_json["proof"],
                content_json["endorserId"],
                content_json["endorsement"],
            )
    raise NotImplementedError(
        "Response deserialize not implemented"
    )  # pragma: no cover
