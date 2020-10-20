"""Type annotations used by the library."""
from typing import Dict
from typing import List
from typing import Union

import httpx

from ._entity import Asset
from ._entity import AssetType
from ._entity import Identity


Entity = Union[Identity, AssetType, Asset]
Iov42Header = Union[Dict[str, str], List[Dict[str, str]]]

URL = httpx.URL
URLTypes = Union[URL, str]
