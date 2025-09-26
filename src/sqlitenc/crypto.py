import hashlib
import hmac
import json
import os
import unicodedata
from dataclasses import dataclass
from typing import List

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _normalize_text(value: str) -> str:
    # nfkc + lowercase to normalise variations
    return unicodedata.normalize("NFKC", value).lower()


def _to_bytes(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    # serialize types into json
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


@dataclass
class AesGcmCipher:
    key: bytes

    def encrypt(self, value: object, aad: bytes | None = None) -> bytes:
        aesgcm = AESGCM(self.key)
        nonce = os.urandom(12)
        plaintext = _to_bytes(value)
        ct = aesgcm.encrypt(nonce, plaintext, aad)
        return nonce + ct

    def decrypt(self, payload: bytes, aad: bytes | None = None) -> bytes:
        aesgcm = AESGCM(self.key)
        nonce, ct = payload[:12], payload[12:]
        return aesgcm.decrypt(nonce, ct, aad)


def compute_primary_blind_index(index_key: bytes, value: str) -> bytes:
    normalized = _normalize_text(value)
    digest = hmac.new(index_key, normalized.encode("utf-8"), hashlib.sha256).digest()
    return digest[:16]


def generate_ngrams(value: str, n: int = 3) -> List[str]:
    normalized = _normalize_text(value)
    if len(normalized) < n:
        return [normalized]
    return [normalized[i : i + n] for i in range(len(normalized) - n + 1)]


def compute_ngram_hashes(index_key: bytes, value: str, n: int = 3) -> List[bytes]:
    ngrams = generate_ngrams(value, n=n)
    return [hmac.new(index_key, ng.encode("utf-8"), hashlib.sha256).digest()[:12] for ng in ngrams]


@dataclass
class BlindIndexer:
    index_key: bytes
    ngram_size: int = 3

    def primary(self, value: str) -> bytes:
        return compute_primary_blind_index(self.index_key, value)

    def ngrams(self, value: str) -> List[bytes]:
        return compute_ngram_hashes(self.index_key, value, n=self.ngram_size)


