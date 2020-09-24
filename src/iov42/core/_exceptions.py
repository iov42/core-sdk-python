"""Exceptions thrown by the library."""


class PlatformError(Exception):
    """Base class for platform errors."""

    def __init__(self, message: str) -> None:
        """Initialize PlatformError exception.

        Args:
            message: error message
        """
        super().__init__(message)


# TODO: The name is misleading, maybe we should call it EntityAlreadyExists.
class AssetAlreadyExists(PlatformError):
    """The asset (identity, asset type, assets, etc.) already exists."""

    # TODO maaybe we should use 'address' instead of 'id'
    def __init__(self, message: str, request_id: str, id: str) -> None:
        """Initialize AssetAlreadyExists exception.

        Args:
            message: error message
            request_id: request identifier from which the response is originating
            id: entity identifier
        """
        super().__init__(message)
        self.request_id = request_id
        self.id = id


class DuplicateRequestId(PlatformError):
    """The provided request identifier was already used."""

    def __init__(self, message: str, request_id: str) -> None:
        """Initialize DuplicateRequestId exception.

        Args:
            message: error message
            request_id: request identifier from which the response is originating
        """
        super().__init__(message)
        self.request_id = request_id
