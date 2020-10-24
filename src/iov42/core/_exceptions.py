"""Exceptions thrown by the library."""
# TODO: enable code coverage checks when we implemented exception handling.


class PlatformError(Exception):  # pragma: no cover
    """Base class for platform errors."""

    def __init__(self, message: str) -> None:
        """Initialize PlatformError exception.

        Args:
            message: error message
        """
        super().__init__(message)


# TODO: The name is misleading, maybe we should call it EntityAlreadyExists.
class AssetAlreadyExists(PlatformError):  # pragma: no cover
    """The asset (identity, asset type, assets, etc.) already exists."""

    def __init__(self, message: str, request_id: str) -> None:
        """Initialize AssetAlreadyExists exception.

        Args:
            message: error message
            request_id: request identifier from which the response is originating
        """
        super().__init__(message)
        self.request_id = request_id


class DuplicateRequestId(PlatformError):  # pragma: no cover
    """The provided request identifier was already used."""

    def __init__(self, message: str, request_id: str) -> None:
        """Initialize DuplicateRequestId exception.

        Args:
            message: error message
            request_id: request identifier from which the response is originating
        """
        super().__init__(message)
        self.request_id = request_id
