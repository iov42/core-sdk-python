"""Type annotations used by the library."""
from typing import Dict
from typing import List
from typing import Union

Claims = List[bytes]
Signature = Dict[str, str]
Authorisations = List[Signature]
Iov42Header = Union[Signature, Authorisations]
