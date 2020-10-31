"""Test cases for iov42.core.Client."""
from unittest import mock

from iov42.core import Client
from iov42.core import PrivateIdentity
from iov42.core._httpclient import HttpClient


def test_propagate_close(identity: PrivateIdentity) -> None:
    """Propagate close to the wrapped HTTP client implementation."""
    with mock.patch.object(HttpClient, "close") as mocked_close:
        client = Client("https://example.org", identity)

        client.close()

        mocked_close.assert_called_once_with()


def test_close_on_del(identity: PrivateIdentity) -> None:
    """Resources are freed on deleting the object."""
    with mock.patch.object(HttpClient, "close") as mocked_close:
        client = Client("https://example.org", identity)

        del client

        mocked_close.assert_called_once_with()


def test_context_manager(identity: PrivateIdentity) -> None:
    """Close connection when leaving the context manager."""
    with mock.patch.object(HttpClient, "close") as mocked_close:
        with Client("https://example.org", identity) as _:
            pass

        mocked_close.assert_called_once_with()
