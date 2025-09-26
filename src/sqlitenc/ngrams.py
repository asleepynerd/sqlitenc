from __future__ import annotations

from sqlalchemy import BLOB, INTEGER, TEXT, Column, Index, MetaData, Table


# global metadata for the helper table
_metadata = MetaData()

sqlitenc_ngrams = Table(
    "sqlitenc_ngrams",
    _metadata,
    Column("table_name", TEXT, nullable=False),
    Column("row_id", INTEGER, nullable=False),
    Column("field", TEXT, nullable=False),
    Column("h", BLOB, nullable=False),
    Index("ix_sqlitenc_ngrams_lookup", "table_name", "field", "h"),
    Index("ix_sqlitenc_ngrams_row", "table_name", "field", "row_id"),
)
def create_ngrams_table(engine) -> None:
    _metadata.create_all(engine, tables=[sqlitenc_ngrams])


