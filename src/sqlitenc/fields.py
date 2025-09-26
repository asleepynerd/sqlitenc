from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from sqlalchemy import BINARY, Column, Index, LargeBinary, String, event
from sqlalchemy.orm import Mapped, mapped_column

from .crypto import AesGcmCipher, BlindIndexer
from .keys import KeyProvider


@dataclass
class EncryptedScalar:
    name: str
    key_provider: KeyProvider
    indexer: BlindIndexer

    def storage_columns(self) -> list[Column]:
        return [
            mapped_column(name=f"{self.name}_ct", type_=LargeBinary, nullable=True),
            mapped_column(name=f"{self.name}_pbi", type_=BINARY(16), index=True, nullable=True),
            mapped_column(name=f"{self.name}_ngr", type_=LargeBinary, nullable=True),
        ]

    def setup_on_class(self, cls: Any) -> None:
        # sqlalchemy indices
        Index(f"ix_{cls.__tablename__}_{self.name}_pbi", getattr(cls, f"{self.name}_pbi"))

        # attribute events
        target_attr = self.name

        def set_handler(target, value, oldvalue, initiator):
            if value is None:
                setattr(target, f"{self.name}_ct", None)
                setattr(target, f"{self.name}_pbi", None)
                setattr(target, f"{self.name}_ngr", None)
                return value

            cipher = AesGcmCipher(self.key_provider.get_data_key())
            pbi = self.indexer.primary(str(value))
            ngr_list = self.indexer.ngrams(str(value))
            # store ngrams as concatenated bytes
            ngr_serialized = b"".join(len(x).to_bytes(1, "big") + x for x in ngr_list)
            ct = cipher.encrypt(str(value))
            setattr(target, f"{self.name}_ct", ct)
            setattr(target, f"{self.name}_pbi", pbi)
            setattr(target, f"{self.name}_ngr", ngr_serialized)
            return value

        event.listen(getattr(cls, target_attr), "set", set_handler, retval=True)
def setup_encrypted_string(
    name: str,
    key_provider: KeyProvider,
    indexer: BlindIndexer,
) -> EncryptedScalar:
    return EncryptedScalar(name=name, key_provider=key_provider, indexer=indexer)
