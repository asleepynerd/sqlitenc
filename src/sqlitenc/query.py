from __future__ import annotations

from typing import Any

from sqlalchemy import and_, func

from .crypto import BlindIndexer


def equals_encrypted(model, field_name: str, value: str, indexer: BlindIndexer):
    pbi_col = getattr(model, f"{field_name}_pbi")
    target = indexer.primary(value)
    return pbi_col == target

def contains_encrypted(model, field_name: str, value: str, indexer: BlindIndexer):
    ngr_col = getattr(model, f"{field_name}_ngr")
    hashes = indexer.ngrams(value)
    clauses = [func.instr(ngr_col, len(h).to_bytes(1, "big") + h) > 0 for h in hashes]
    return and_(*clauses) if clauses else Tru
