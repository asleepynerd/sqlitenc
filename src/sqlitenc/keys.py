import base64
import os
from dataclasses import dataclass
from typing import Protocol

class KeyProvider(Protocol):
    def get_data_key(self) -> bytes: # aes-256-gcm
        ...

    def get_index_key(self) -> bytes:  # hmac key - 32 bytes
        ...
@dataclass
class StaticKeyProvider:
    data_key: bytes
    index_key: bytes

    @classmethod
    def from_env(cls, data_var: str = "SQLITENC_DATA_KEY", index_var: str = "SQLITENC_INDEX_KEY") -> "StaticKeyProvider":
        dk = os.environ.get(data_var)
        ik = os.environ.get(index_var)
        if not dk or not ik:
            raise RuntimeError("Missing encryption keys in environment")
        return cls(base64.b64decode(dk), base64.b64decode(ik))
    def get_data_key(self) -> bytes:
        return self.data_key
    def get_index_key(self) -> bytes:
        return self.index_key


