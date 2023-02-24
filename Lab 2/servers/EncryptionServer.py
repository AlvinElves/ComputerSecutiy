from .DHServer import DHServer
from .RSAServer import RSAServer
from .SymmetricServer import SymmetricServer

class EncryptionServer(SymmetricServer, DHServer, RSAServer):
    def __init__(self):
        super().__init__()
        self._shared_key = None

