from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import BINARY, Column, Index, LargeBinary, event
from sqlalchemy.orm import Session, mapped_column

from .crypto import AesGcmCipher, BlindIndexer
from .keys import KeyProvider
from .ngrams import sqlitenc_ngrams


@dataclass
class EncryptedScalar:
    name: str
    key_provider: KeyProvider
    indexer: BlindIndexer

    def storage_columns(self) -> list[Column]:
        return [
            mapped_column(name=f"{self.name}_ct", type_=LargeBinary, nullable=True),
            mapped_column(name=f"{self.name}_pbi", type_=BINARY(16), index=True, nullable=True),
            # no per-row n-gram blob when using join table
        ]

    def setup_on_class(self, cls: Any) -> None:
        # sqlalchemy indices
        Index(f"ix_{cls.__tablename__}_{self.name}_pbi", getattr(cls, f"{self.name}_pbi"))

        # attribute events
        target_attr = self.name

        def set_handler(target, value, _oldvalue, _initiator):
            if value is None:
                setattr(target, f"{self.name}_ct", None)
                setattr(target, f"{self.name}_pbi", None)
                return value

            cipher = AesGcmCipher(self.key_provider.get_data_key())
            pbi = self.indexer.primary(str(value))
            ct = cipher.encrypt(str(value))
            setattr(target, f"{self.name}_ct", ct)
            setattr(target, f"{self.name}_pbi", pbi)
            # Defer n-gram join-table updates to after_flush event
            return value

        event.listen(getattr(cls, target_attr), "set", set_handler, retval=True)

        @event.listens_for(Session, "after_flush")
        def update_ngrams(session, _ctx):
            for instance in session.new.union(session.dirty):
                if not isinstance(instance, cls):
                    continue
                val = getattr(instance, self.name, None)
                rowid = getattr(instance, "id", None)
                if rowid is None:
                    continue
                # delete existing
                session.execute(
                    sqlitenc_ngrams.delete().where(
                        (sqlitenc_ngrams.c.table_name == cls.__tablename__) &
                        (sqlitenc_ngrams.c.field == self.name) &
                        (sqlitenc_ngrams.c.row_id == rowid)
                    )
                )
                if val is None:
                    continue
                for h in self.indexer.ngrams(str(val)):
                    session.execute(sqlitenc_ngrams.insert().values(
                        table_name=cls.__tablename__, field=self.name, row_id=rowid, h=h
                    ))
def setup_encrypted_string(
    name: str,
    key_provider: KeyProvider,
    indexer: BlindIndexer,
) -> EncryptedScalar:
    return EncryptedScalar(name=name, key_provider=key_provider, indexer=indexer)
