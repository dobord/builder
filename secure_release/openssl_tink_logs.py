"""LOCAL-only OpenSSL reader for existing builder encrypted CI log artifacts.

This is a decrypt-only compatibility implementation for the current VCPKGSE1
wire format. Encryption and release authorization remain owned by Tink and
secure_release.crypto.
"""
from __future__ import annotations

import base64
import ctypes
import ctypes.util
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import struct
import sys
import tarfile
import tempfile
from typing import Any, BinaryIO

MAGIC = b"VCPKGSE1"
MAX_HEADER = 16384
MAX_CIPHERTEXT_BYTES = 256 * 1024**2
MAX_SINGLE_FILE = 128 * 1024**2
MAX_TOTAL_BYTES = 2 * 1024**3
MAX_FILES = 20000
MAX_DEPTH = 20
MAX_KEYSET_BYTES = 1024 * 1024

HPKE_PRIVATE_TYPE = "type.googleapis.com/google.crypto.tink.HpkePrivateKey"
HPKE_PUBLIC_TYPE = "type.googleapis.com/google.crypto.tink.HpkePublicKey"
STREAMING_TYPE = "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey"

KEM_SUITE = b"KEM\x00\x20"
HPKE_SUITE = b"HPKE\x00\x20\x00\x01\x00\x02"
SEGMENT_SIZE = 1024 * 1024
DERIVED_KEY_SIZE = 32
STREAM_HEADER_SIZE = 40
TAG_SIZE = 16
HASH_SHA256_ENUM = 3

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RESERVED = re.compile(r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)", re.I)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def parse_json(data: bytes | str) -> Any:
    return json.loads(
        data,
        object_pairs_hook=_unique,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError("non-finite JSON value: " + value)
        ),
    )


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _b64(value: str, label: str, limit: int) -> bytes:
    if not isinstance(value, str) or not value or len(value) > limit * 2:
        raise ValueError("invalid " + label + " base64 length")
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as error:
        raise ValueError("invalid " + label + " base64") from error
    if not raw or len(raw) > limit:
        raise ValueError("invalid " + label + " decoded length")
    return raw


def decode_private_key_text(value: str) -> str:
    """Accept decoded Tink JSON or the builder base64 transport form."""
    if not isinstance(value, str) or not value.strip() or len(value) > 2 * MAX_KEYSET_BYTES:
        raise ValueError("invalid private key text length")
    value = value.strip()
    raw = value.encode("utf-8") if value.startswith("{") else _b64(
        value, "private key", MAX_KEYSET_BYTES
    )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("private key is not UTF-8 JSON") from error
    if not isinstance(parse_json(text), dict):
        raise ValueError("private key must be a JSON object")
    return text


def _varint(data: bytes, offset: int) -> tuple[int, int]:
    value = shift = 0
    for _ in range(10):
        if offset >= len(data):
            raise ValueError("truncated protobuf varint")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
        shift += 7
    raise ValueError("oversized protobuf varint")


def _proto(data: bytes) -> dict[int, list[int | bytes]]:
    offset = 0
    result: dict[int, list[int | bytes]] = {}
    while offset < len(data):
        tag, offset = _varint(data, offset)
        field, wire = tag >> 3, tag & 7
        if field <= 0:
            raise ValueError("invalid protobuf field")
        if wire == 0:
            value, offset = _varint(data, offset)
        elif wire == 2:
            size, offset = _varint(data, offset)
            if offset + size > len(data):
                raise ValueError("truncated protobuf bytes")
            value = data[offset:offset + size]
            offset += size
        else:
            raise ValueError("unsupported protobuf wire type")
        result.setdefault(field, []).append(value)
    return result


def _only(fields, allowed, label):
    if set(fields) - set(allowed):
        raise ValueError("unexpected " + label + " protobuf fields")


def _one(fields, number, label, required=True):
    values = fields.get(number, [])
    if not values:
        if required:
            raise ValueError("missing " + label)
        return None
    if len(values) != 1:
        raise ValueError("duplicate " + label)
    return values[0]


def _version0(fields, label):
    if _one(fields, 1, label + " version", False) not in (None, 0):
        raise ValueError("unsupported " + label + " version")


class OpenSSLBackend:
    """Minimal OpenSSL 3 libcrypto binding for X25519, HMAC-SHA256 and AES-GCM."""

    SET_IVLEN = 0x9
    SET_TAG = 0x11

    def __init__(self, library: str | None = None):
        candidate = library or os.environ.get("BUILDER_OPENSSL_CRYPTO_LIBRARY")
        names = [candidate or ctypes.util.find_library("crypto")]
        if os.name == "nt":
            names += ["libcrypto-3-x64.dll", "libcrypto-3.dll"]
        elif sys.platform == "darwin":
            names += ["libcrypto.3.dylib", "libcrypto.dylib"]
        else:
            names += ["libcrypto.so.3", "libcrypto.so"]

        self.lib = None
        last = None
        for name in dict.fromkeys(item for item in names if item):
            try:
                self.lib = ctypes.CDLL(name)
                self.library_name = name
                break
            except OSError as error:
                last = error
        if self.lib is None:
            raise RuntimeError(
                "OpenSSL libcrypto not found; install OpenSSL 3 or set "
                "BUILDER_OPENSSL_CRYPTO_LIBRARY"
            ) from last
        self._bind()
        if self.lib.OpenSSL_version_num() < 0x30000000:
            raise RuntimeError("OpenSSL 3.0 or newer is required")
        raw = self.lib.OpenSSL_version(0)
        self.version = raw.decode("ascii", "replace") if raw else "OpenSSL 3"

    def _bind(self):
        L = self.lib
        L.OpenSSL_version_num.restype = ctypes.c_ulong
        L.OpenSSL_version.argtypes = [ctypes.c_int]
        L.OpenSSL_version.restype = ctypes.c_char_p

        L.EVP_sha256.restype = ctypes.c_void_p
        L.HMAC.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int,
            ctypes.c_void_p, ctypes.c_size_t,
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint),
        ]
        L.HMAC.restype = ctypes.c_void_p

        for name in (
            "EVP_PKEY_new_raw_private_key_ex",
            "EVP_PKEY_new_raw_public_key_ex",
            "EVP_PKEY_CTX_new_from_pkey",
        ):
            if not hasattr(L, name):
                raise RuntimeError("OpenSSL 3 raw X25519 API unavailable")
        L.EVP_PKEY_new_raw_private_key_ex.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_void_p, ctypes.c_size_t,
        ]
        L.EVP_PKEY_new_raw_private_key_ex.restype = ctypes.c_void_p
        L.EVP_PKEY_new_raw_public_key_ex.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_void_p, ctypes.c_size_t,
        ]
        L.EVP_PKEY_new_raw_public_key_ex.restype = ctypes.c_void_p
        L.EVP_PKEY_get_raw_public_key.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)
        ]
        L.EVP_PKEY_get_raw_public_key.restype = ctypes.c_int
        L.EVP_PKEY_free.argtypes = [ctypes.c_void_p]
        L.EVP_PKEY_CTX_new_from_pkey.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p
        ]
        L.EVP_PKEY_CTX_new_from_pkey.restype = ctypes.c_void_p
        L.EVP_PKEY_CTX_free.argtypes = [ctypes.c_void_p]
        L.EVP_PKEY_derive_init.argtypes = [ctypes.c_void_p]
        L.EVP_PKEY_derive_init.restype = ctypes.c_int
        L.EVP_PKEY_derive_set_peer.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        L.EVP_PKEY_derive_set_peer.restype = ctypes.c_int
        L.EVP_PKEY_derive.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)
        ]
        L.EVP_PKEY_derive.restype = ctypes.c_int

        L.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
        L.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
        L.EVP_aes_256_gcm.restype = ctypes.c_void_p
        L.EVP_DecryptInit_ex.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_void_p, ctypes.c_void_p,
        ]
        L.EVP_DecryptInit_ex.restype = ctypes.c_int
        L.EVP_DecryptUpdate.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int),
            ctypes.c_void_p, ctypes.c_int,
        ]
        L.EVP_DecryptUpdate.restype = ctypes.c_int
        L.EVP_DecryptFinal_ex.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)
        ]
        L.EVP_DecryptFinal_ex.restype = ctypes.c_int
        L.EVP_CIPHER_CTX_ctrl.argtypes = [
            ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p
        ]
        L.EVP_CIPHER_CTX_ctrl.restype = ctypes.c_int

    @staticmethod
    def _buf(data: bytes):
        return None if not data else (ctypes.c_ubyte * len(data)).from_buffer_copy(data)

    def hmac_sha256(self, key: bytes, data: bytes) -> bytes:
        output = (ctypes.c_ubyte * 32)()
        size = ctypes.c_uint()
        if not self.lib.HMAC(
            self.lib.EVP_sha256(), self._buf(key), len(key),
            self._buf(data), len(data), output, ctypes.byref(size)
        ) or size.value != 32:
            raise RuntimeError("OpenSSL HMAC-SHA256 failed")
        return bytes(output)

    def _private(self, key: bytes):
        if len(key) != 32:
            raise ValueError("X25519 private key must be 32 bytes")
        handle = self.lib.EVP_PKEY_new_raw_private_key_ex(
            None, b"X25519", None, self._buf(key), 32
        )
        if not handle:
            raise ValueError("OpenSSL rejected X25519 private key")
        return handle

    def x25519_public(self, private: bytes) -> bytes:
        handle = self._private(private)
        try:
            output = (ctypes.c_ubyte * 32)()
            size = ctypes.c_size_t(32)
            if self.lib.EVP_PKEY_get_raw_public_key(
                handle, output, ctypes.byref(size)
            ) != 1 or size.value != 32:
                raise RuntimeError("OpenSSL X25519 public derivation failed")
            return bytes(output)
        finally:
            self.lib.EVP_PKEY_free(handle)

    def x25519_shared(self, private: bytes, peer: bytes) -> bytes:
        if len(peer) != 32:
            raise ValueError("X25519 peer key must be 32 bytes")
        own = self._private(private)
        other = self.lib.EVP_PKEY_new_raw_public_key_ex(
            None, b"X25519", None, self._buf(peer), 32
        )
        if not other:
            self.lib.EVP_PKEY_free(own)
            raise ValueError("OpenSSL rejected X25519 peer key")
        ctx = None
        try:
            ctx = self.lib.EVP_PKEY_CTX_new_from_pkey(None, own, None)
            if not ctx or self.lib.EVP_PKEY_derive_init(ctx) != 1:
                raise RuntimeError("OpenSSL X25519 derive init failed")
            if self.lib.EVP_PKEY_derive_set_peer(ctx, other) != 1:
                raise ValueError("OpenSSL rejected X25519 peer key")
            size = ctypes.c_size_t()
            if self.lib.EVP_PKEY_derive(ctx, None, ctypes.byref(size)) != 1:
                raise RuntimeError("OpenSSL X25519 derive size failed")
            output = (ctypes.c_ubyte * size.value)()
            if size.value != 32 or self.lib.EVP_PKEY_derive(
                ctx, output, ctypes.byref(size)
            ) != 1:
                raise ValueError("OpenSSL X25519 derive failed")
            shared = bytes(output[:size.value])
            if not any(shared):
                raise ValueError("invalid all-zero X25519 secret")
            return shared
        finally:
            if ctx:
                self.lib.EVP_PKEY_CTX_free(ctx)
            self.lib.EVP_PKEY_free(other)
            self.lib.EVP_PKEY_free(own)

    def aes256_gcm_decrypt(
        self, key: bytes, nonce: bytes, ciphertext_tag: bytes, aad: bytes = b""
    ) -> bytes:
        if len(key) != 32 or len(nonce) != 12 or len(ciphertext_tag) < TAG_SIZE:
            raise ValueError("invalid AES-256-GCM input")
        ciphertext, tag = ciphertext_tag[:-TAG_SIZE], ciphertext_tag[-TAG_SIZE:]
        ctx = self.lib.EVP_CIPHER_CTX_new()
        if not ctx:
            raise RuntimeError("OpenSSL AES-GCM allocation failed")
        output = (ctypes.c_ubyte * max(1, len(ciphertext)))()
        written = ctypes.c_int()
        final_written = ctypes.c_int()
        try:
            if self.lib.EVP_DecryptInit_ex(
                ctx, self.lib.EVP_aes_256_gcm(), None, None, None
            ) != 1:
                raise RuntimeError("OpenSSL AES-GCM init failed")
            if self.lib.EVP_CIPHER_CTX_ctrl(
                ctx, self.SET_IVLEN, len(nonce), None
            ) != 1:
                raise RuntimeError("OpenSSL AES-GCM IV setup failed")
            if self.lib.EVP_DecryptInit_ex(
                ctx, None, None, self._buf(key), self._buf(nonce)
            ) != 1:
                raise RuntimeError("OpenSSL AES-GCM key setup failed")
            if aad:
                ignored = ctypes.c_int()
                if self.lib.EVP_DecryptUpdate(
                    ctx, None, ctypes.byref(ignored), self._buf(aad), len(aad)
                ) != 1:
                    raise RuntimeError("OpenSSL AES-GCM AAD setup failed")
            if ciphertext and self.lib.EVP_DecryptUpdate(
                ctx, output, ctypes.byref(written),
                self._buf(ciphertext), len(ciphertext)
            ) != 1:
                raise RuntimeError("OpenSSL AES-GCM decrypt failed")
            if self.lib.EVP_CIPHER_CTX_ctrl(
                ctx, self.SET_TAG, TAG_SIZE, self._buf(tag)
            ) != 1:
                raise RuntimeError("OpenSSL AES-GCM tag setup failed")
            tail = (ctypes.c_ubyte * TAG_SIZE)()
            if self.lib.EVP_DecryptFinal_ex(
                ctx, tail, ctypes.byref(final_written)
            ) != 1:
                raise ValueError("AES-GCM authentication failed")
            return bytes(output[:written.value]) + bytes(tail[:final_written.value])
        finally:
            self.lib.EVP_CIPHER_CTX_free(ctx)


def _extract(backend, salt, ikm):
    return backend.hmac_sha256(salt or b"\0" * 32, ikm)


def _expand(backend, prk, info, size):
    if not 0 <= size <= 255 * 32:
        raise ValueError("HKDF output outside RFC5869 bounds")
    output = bytearray()
    block = b""
    for index in range(1, (size + 31) // 32 + 1):
        block = backend.hmac_sha256(prk, block + info + bytes([index]))
        output.extend(block)
    return bytes(output[:size])


def _hkdf(backend, ikm, salt, info, size):
    return _expand(backend, _extract(backend, salt, ikm), info, size)


def _lextract(backend, suite, label, ikm, salt=b""):
    return _extract(backend, salt, b"HPKE-v1" + suite + label + ikm)


def _lexpand(backend, suite, prk, label, info, size):
    return _expand(
        backend, prk,
        size.to_bytes(2, "big") + b"HPKE-v1" + suite + label + info,
        size,
    )


def _private_keyset(text: str, backend: OpenSSLBackend):
    value = parse_json(text)
    if not isinstance(value, dict) or set(value) != {"primaryKeyId", "key"}:
        raise ValueError("unexpected Tink private keyset")
    if not isinstance(value["key"], list) or len(value["key"]) != 1:
        raise ValueError("exactly one Tink private key required")
    entry = value["key"][0]
    if not isinstance(entry, dict) or set(entry) != {
        "keyData", "status", "keyId", "outputPrefixType"
    }:
        raise ValueError("unexpected Tink private key entry")
    key_id = entry["keyId"]
    if (
        type(key_id) is not int or key_id <= 0 or value["primaryKeyId"] != key_id
        or entry["status"] != "ENABLED" or entry["outputPrefixType"] != "TINK"
    ):
        raise ValueError("unsupported Tink private key metadata")
    data = entry["keyData"]
    if not isinstance(data, dict) or set(data) != {
        "typeUrl", "value", "keyMaterialType"
    } or data["typeUrl"] != HPKE_PRIVATE_TYPE or data["keyMaterialType"] != "ASYMMETRIC_PRIVATE":
        raise ValueError("private key is not required Tink HPKE type")

    private = _proto(_b64(data["value"], "HPKE private proto", 4096))
    _only(private, {1, 2, 3}, "HPKE private key")
    _version0(private, "HPKE private key")
    public_proto = _one(private, 2, "HPKE public key")
    private_bytes = _one(private, 3, "HPKE private bytes")
    if not isinstance(public_proto, bytes) or not isinstance(private_bytes, bytes):
        raise ValueError("invalid HPKE private key protobuf")

    public = _proto(public_proto)
    _only(public, {1, 2, 3}, "HPKE public key")
    _version0(public, "HPKE public key")
    params_proto = _one(public, 2, "HPKE params")
    public_bytes = _one(public, 3, "HPKE public bytes")
    if not isinstance(params_proto, bytes) or not isinstance(public_bytes, bytes):
        raise ValueError("invalid HPKE public key protobuf")
    params = _proto(params_proto)
    _only(params, {1, 2, 3}, "HPKE params")
    if (
        _one(params, 1, "HPKE KEM") != 1
        or _one(params, 2, "HPKE KDF") != 1
        or _one(params, 3, "HPKE AEAD") != 2
        or len(private_bytes) != 32 or len(public_bytes) != 32
        or backend.x25519_public(private_bytes) != public_bytes
    ):
        raise ValueError("unsupported or inconsistent HPKE key")

    public_keyset = {
        "primaryKeyId": key_id,
        "key": [{
            "keyData": {
                "typeUrl": HPKE_PUBLIC_TYPE,
                "value": base64.b64encode(public_proto).decode("ascii"),
                "keyMaterialType": "ASYMMETRIC_PUBLIC",
            },
            "status": "ENABLED",
            "keyId": key_id,
            "outputPrefixType": "TINK",
        }],
    }
    return {
        "key_id": key_id,
        "private": private_bytes,
        "public": public_bytes,
        "recipient": hashlib.sha256(canonical(public_keyset)).hexdigest(),
    }


def _streaming_keyset(data: bytes):
    value = parse_json(data)
    if not isinstance(value, dict) or set(value) != {"primaryKeyId", "key"}:
        raise ValueError("unexpected Tink streaming keyset")
    if not isinstance(value["key"], list) or len(value["key"]) != 1:
        raise ValueError("exactly one Tink streaming key required")
    entry = value["key"][0]
    if not isinstance(entry, dict) or set(entry) != {
        "keyData", "status", "keyId", "outputPrefixType"
    }:
        raise ValueError("unexpected Tink streaming key entry")
    if (
        type(entry["keyId"]) is not int or entry["keyId"] <= 0
        or value["primaryKeyId"] != entry["keyId"]
        or entry["status"] != "ENABLED" or entry["outputPrefixType"] != "RAW"
    ):
        raise ValueError("unsupported Tink streaming key metadata")
    kd = entry["keyData"]
    if not isinstance(kd, dict) or set(kd) != {
        "typeUrl", "value", "keyMaterialType"
    } or kd["typeUrl"] != STREAMING_TYPE or kd["keyMaterialType"] != "SYMMETRIC":
        raise ValueError("wrapped key is not AES256_GCM_HKDF_1MB")

    fields = _proto(_b64(kd["value"], "streaming key proto", 4096))
    _only(fields, {1, 2, 3}, "streaming key")
    _version0(fields, "streaming key")
    params_proto = _one(fields, 2, "streaming params")
    key = _one(fields, 3, "streaming key bytes")
    if not isinstance(params_proto, bytes) or not isinstance(key, bytes):
        raise ValueError("invalid streaming key protobuf")
    params = _proto(params_proto)
    _only(params, {1, 2, 3}, "streaming params")
    if (
        _one(params, 1, "segment size") != SEGMENT_SIZE
        or _one(params, 2, "derived key size") != DERIVED_KEY_SIZE
        or _one(params, 3, "HKDF hash") != HASH_SHA256_ENUM
        or len(key) != 32
    ):
        raise ValueError("unsupported streaming key parameters")
    return key


def _envelope(source: BinaryIO):
    if source.read(len(MAGIC)) != MAGIC:
        raise ValueError("unsupported encrypted-log envelope")
    raw_len = source.read(4)
    if len(raw_len) != 4:
        raise ValueError("truncated encrypted-log envelope")
    size = struct.unpack(">I", raw_len)[0]
    if not 1 <= size <= MAX_HEADER:
        raise ValueError("invalid encrypted-log header size")
    raw = source.read(size)
    if len(raw) != size:
        raise ValueError("truncated encrypted-log header")
    header = parse_json(raw)
    if (
        not isinstance(header, dict)
        or set(header) != {"version", "context", "recipient", "wrapped"}
        or header["version"] != 1 or canonical(header) != raw
    ):
        raise ValueError("invalid encrypted-log header")
    context = header["context"]
    if not isinstance(context, dict) or set(context) != {
        "schema", "kind", "repository", "workflow", "job",
        "run_id", "run_attempt", "sha"
    }:
        raise ValueError("invalid encrypted-log context")
    if (
        context["schema"] != 1 or context["kind"] != "builder-encrypted-ci-logs"
        or type(context["run_id"]) is not int or type(context["run_attempt"]) is not int
        or context["run_id"] < 0 or context["run_attempt"] < 0
        or not all(
            isinstance(context[name], str) and 0 < len(context[name]) <= 256
            for name in ("repository", "workflow", "job", "sha")
        )
        or not isinstance(header["recipient"], str)
        or _SHA256.fullmatch(header["recipient"]) is None
    ):
        raise ValueError("invalid encrypted-log context values")
    return header


def _unwrap(backend, header, private):
    if header["recipient"] != private["recipient"]:
        raise ValueError("wrong encrypted-log recipient")
    wrapped = _b64(header["wrapped"], "wrapped key", MAX_HEADER)
    prefix = b"\x01" + private["key_id"].to_bytes(4, "big")
    if len(wrapped) < 53 or wrapped[:5] != prefix:
        raise ValueError("wrong Tink HPKE output prefix")
    enc, ciphertext = wrapped[5:37], wrapped[37:]

    dh = backend.x25519_shared(private["private"], enc)
    eae = _lextract(backend, KEM_SUITE, b"eae_prk", dh)
    shared = _lexpand(
        backend, KEM_SUITE, eae, b"shared_secret", enc + private["public"], 32
    )
    info = b"vcpkg-file-key-v1\0" + canonical(header["context"])
    schedule = (
        b"\0"
        + _lextract(backend, HPKE_SUITE, b"psk_id_hash", b"")
        + _lextract(backend, HPKE_SUITE, b"info_hash", info)
    )
    secret = _lextract(backend, HPKE_SUITE, b"secret", b"", shared)
    key = _lexpand(backend, HPKE_SUITE, secret, b"key", schedule, 32)
    nonce = _lexpand(backend, HPKE_SUITE, secret, b"base_nonce", schedule, 12)
    plaintext = backend.aes256_gcm_decrypt(key, nonce, ciphertext)
    if len(plaintext) > MAX_KEYSET_BYTES:
        raise ValueError("wrapped streaming keyset oversized")
    return _streaming_keyset(plaintext)


def validate_ciphertext(path: Path) -> Path:
    path = path.expanduser().resolve(strict=True)
    if not path.is_file() or path.is_symlink():
        raise ValueError("ciphertext must be a regular file")
    if not 0 < path.stat().st_size <= MAX_CIPHERTEXT_BYTES:
        raise ValueError("ciphertext size outside local diagnostic limit")
    return path


def _decrypt_stream(source_path, plaintext_path, private_text, backend):
    source_path = validate_ciphertext(source_path)
    private = _private_keyset(private_text, backend)
    total = source_path.stat().st_size
    with source_path.open("rb") as source:
        header = _envelope(source)
        stream_key = _unwrap(backend, header, private)
        stream_header = source.read(STREAM_HEADER_SIZE)
        if len(stream_header) != STREAM_HEADER_SIZE or stream_header[0] != STREAM_HEADER_SIZE:
            raise ValueError("invalid Tink streaming header")
        derived = _hkdf(
            backend, stream_key, stream_header[1:33],
            b"vcpkg-stream-v1\0" + canonical(header), DERIVED_KEY_SIZE
        )
        prefix = stream_header[33:40]

        fd, name = tempfile.mkstemp(
            prefix=".openssl-log-decrypt-", dir=plaintext_path.parent
        )
        os.close(fd)
        temporary = Path(name)
        try:
            plain_total = index = 0
            with temporary.open("wb") as output:
                while source.tell() < total:
                    capacity = SEGMENT_SIZE - STREAM_HEADER_SIZE if index == 0 else SEGMENT_SIZE
                    remaining = total - source.tell()
                    size = min(capacity, remaining)
                    final = size == remaining
                    if size < TAG_SIZE:
                        raise ValueError("truncated Tink streaming segment")
                    segment = source.read(size)
                    if len(segment) != size:
                        raise ValueError("truncated Tink streaming segment")
                    nonce = prefix + index.to_bytes(4, "big") + (
                        b"\x01" if final else b"\x00"
                    )
                    plaintext = backend.aes256_gcm_decrypt(derived, nonce, segment)
                    plain_total += len(plaintext)
                    if plain_total > MAX_CIPHERTEXT_BYTES:
                        raise ValueError("decrypted diagnostic exceeds local limit")
                    output.write(plaintext)
                    index += 1
                    if index > 0xFFFFFFFF:
                        raise ValueError("too many Tink streaming segments")
                if index == 0:
                    raise ValueError("missing Tink streaming segment")
            os.replace(temporary, plaintext_path)
        finally:
            temporary.unlink(missing_ok=True)
    return header


def _safe_name(name: str):
    if (
        not isinstance(name, str) or not name or len(name) > 4096
        or any(char in name for char in '\\:"<>|?*')
        or any(ord(char) < 32 or ord(char) == 127 for char in name)
    ):
        raise ValueError("unsafe encrypted-log archive path")
    path = PurePosixPath(name)
    parts = path.parts
    if (
        path.is_absolute() or len(parts) > MAX_DEPTH
        or any(
            part in ("", ".", "..") or part.endswith((" ", "."))
            or _RESERVED.match(part)
            for part in parts
        )
    ):
        raise ValueError("unsafe encrypted-log archive path")
    return parts


def _manifest(archive, header):
    members = archive.getmembers()
    if len(members) > MAX_FILES + 1:
        raise ValueError("encrypted-log archive has too many members")
    by_name = {}
    total = 0
    for member in members:
        _safe_name(member.name)
        if member.name in by_name:
            raise ValueError("duplicate encrypted-log archive member")
        if member.issym() or member.islnk() or member.isdev() or not (
            member.isfile() or member.isdir()
        ):
            raise ValueError("unsupported encrypted-log archive member")
        if not 0 <= member.size <= MAX_SINGLE_FILE:
            raise ValueError("encrypted-log member exceeds bounded size")
        if member.isfile():
            total += member.size
            if total > MAX_TOTAL_BYTES:
                raise ValueError("encrypted-log archive exceeds bounded size")
        by_name[member.name] = member

    item = by_name.get("manifest.json")
    if item is None or not item.isfile() or item.size > 8 * 1024**2:
        raise ValueError("encrypted-log manifest missing")
    stream = archive.extractfile(item)
    if stream is None:
        raise ValueError("encrypted-log manifest unreadable")
    manifest = parse_json(stream.read())
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {
            "schema", "kind", "context", "recipient",
            "file_count", "plain_bytes", "files"
        }
        or manifest["schema"] != 1
        or manifest["kind"] != "builder-encrypted-ci-log-manifest"
        or manifest["context"] != header["context"]
        or manifest["recipient"] != header["recipient"]
        or type(manifest["file_count"]) is not int
        or type(manifest["plain_bytes"]) is not int
        or not isinstance(manifest["files"], list)
        or manifest["file_count"] != len(manifest["files"])
        or manifest["file_count"] > MAX_FILES
    ):
        raise ValueError("invalid encrypted-log manifest")

    expected = {"manifest.json"}
    plain = 0
    for record in manifest["files"]:
        if not isinstance(record, dict) or set(record) != {
            "archive_name", "relative_path", "bytes", "sha256"
        }:
            raise ValueError("invalid encrypted-log manifest record")
        name = record["archive_name"]
        _safe_name(name)
        if not name.startswith("logs/") or name in expected:
            raise ValueError("invalid encrypted-log manifest archive name")
        if (
            not isinstance(record["relative_path"], str)
            or not record["relative_path"]
            or type(record["bytes"]) is not int
            or not 0 <= record["bytes"] <= MAX_SINGLE_FILE
            or not isinstance(record["sha256"], str)
            or _SHA256.fullmatch(record["sha256"]) is None
        ):
            raise ValueError("invalid encrypted-log manifest metadata")
        member = by_name.get(name)
        if member is None or not member.isfile() or member.size != record["bytes"]:
            raise ValueError("encrypted-log manifest/member mismatch")
        expected.add(name)
        plain += record["bytes"]
    actual = {name for name, member in by_name.items() if member.isfile()}
    if actual != expected or plain != manifest["plain_bytes"]:
        raise ValueError("encrypted-log archive differs from manifest")
    return manifest, by_name


def _extract_archive(plaintext, destination, header):
    destination = destination.expanduser().resolve()
    if destination.exists():
        raise ValueError("decryption destination already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".openssl-log-extract-", dir=destination.parent
    ) as folder:
        staging = Path(folder) / "output"
        staging.mkdir(mode=0o700)
        with tarfile.open(plaintext, "r:gz") as archive:
            manifest, by_name = _manifest(archive, header)
            for record in manifest["files"]:
                name = record["archive_name"]
                source = archive.extractfile(by_name[name])
                if source is None:
                    raise ValueError("encrypted-log member unreadable")
                target = staging.joinpath(*_safe_name(name))
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                digest = hashlib.sha256()
                written = 0
                with target.open("xb") as output:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > record["bytes"]:
                            raise ValueError("encrypted-log member grew during extraction")
                        digest.update(chunk)
                        output.write(chunk)
                if written != record["bytes"] or digest.hexdigest() != record["sha256"]:
                    raise ValueError("encrypted-log member digest mismatch")
                try:
                    target.chmod(0o600)
                except OSError:
                    pass
            manifest_path = staging / "manifest.json"
            manifest_path.write_bytes(canonical(manifest) + b"\n")
            try:
                manifest_path.chmod(0o600)
            except OSError:
                pass
        os.replace(staging, destination)
        return manifest


def decrypt_archive(
    source: Path,
    destination: Path,
    private_key_text: str,
    *,
    openssl_library: str | None = None,
) -> dict:
    """Authenticate and extract one builder encrypted-log .enc file."""
    backend = OpenSSLBackend(openssl_library)
    private_key_text = decode_private_key_text(private_key_text)
    destination = destination.expanduser().resolve()
    if destination.exists():
        raise ValueError("decryption destination already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".openssl-log-decrypt-", dir=destination.parent
    ) as folder:
        plaintext = Path(folder) / "logs.tar.gz"
        header = _decrypt_stream(source, plaintext, private_key_text, backend)
        return _extract_archive(plaintext, destination, header)
