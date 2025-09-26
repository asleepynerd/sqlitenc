from __future__ import annotations

from typing import Any

from sqlalchemy import and_, func, select

from .crypto import BlindIndexer


def equals_encrypted(model, field_name: str, value: str, indexer: BlindIndexer):
    pbi_col = getattr(model, f"{field_name}_pbi")
    target = indexer.primary(value)
    return pbi_col == target

def contains_encrypted(model, field_name: str, value: str, indexer: BlindIndexer, n_required: int | None = None):
    from .ngrams import sqlitenc_ngrams

    hashes = indexer.ngrams(value)
    if not hashes:
        return True
    n_req = n_required if n_required is not None else len(hashes)
    subq = (
        select(sqlitenc_ngrams.c.row_id)
        .where(
            (sqlitenc_ngrams.c.table_name == model.__tablename__) &
            (sqlitenc_ngrams.c.field == field_name) &
            (sqlitenc_ngrams.c.h.in_(hashes))
        )
        .group_by(sqlitenc_ngrams.c.row_id)
        .having(func.count(func.distinct(sqlitenc_ngrams.c.h)) >= n_req)
    )
    pk_col = getattr(model, "id")
    return pk_col.in_(subq)
