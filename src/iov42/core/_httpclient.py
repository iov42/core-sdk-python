"""Interface to the used HTTP client."""
import httpx

from ._request import Request
from ._response import deserialize
from ._response import Response

HttpResponse = httpx.Response


class HttpClient:
    """HTTP client with which we perform the requests."""

    def __init__(self, base_url: str):
        """An HTTP client with connection pooling, HTTP/2, redirects, etc.

        Args:
            base_url: A URL to use as the base when building request URLs.

        """
        self._client = httpx.Client(base_url=base_url)

    @property
    def base_url(self) -> str:
        """Return the base URL."""
        return str(self._client.base_url)

    def get(self, url: str) -> HttpResponse:
        """Send a GET request."""
        # TODO: leaks httpx.Response. Currently used only to read the node_id.
        return self._client.get(url)

    def send(self, request: Request) -> Response:
        """Send request."""
        http_request = self._client.build_request(
            request.method,
            request.url,
            headers=request.headers,
            content=request.content,
        )

        try:
            http_response = self._client.send(http_request)
            http_response.raise_for_status()
        except Exception:
            # TODO: this leaks httpx exceptions. Wrap them in our own
            # exceptions. Othewerwise we leak implementation details about the
            # used HTTP client.
            raise
        response = deserialize(request, http_response.content)
        return response

    def close(self) -> None:
        """Cleanup resources."""
        self._client.close()
