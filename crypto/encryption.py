"""
crypto/encryption.py
----------------------
AES-256-GCM authenticated encryption and decryption, plus a small binary
"payload format" that bundles everything the receiver needs (salt, nonce,
tag, ciphertext) into one blob that steganography/encoder.py can hide
inside an image.

Beginner note on the payload format:
The receiver only has the stego image and the password -- nothing else.
So the encrypted blob we hide must carry its own salt and nonce alongside
the ciphertext and authentication tag. We lay these out in a fixed,
documented binary structure:

    MAGIC (4 bytes)      b"SIMG"  -- lets the extractor recognize our format
    VERSION (1 byte)     format version, for future compatibility
    SALT (16 bytes)      scrypt salt used for key derivation
    NONCE (12 bytes)     AES-GCM nonce
    TAG (16 bytes)       AES-GCM authentication tag
    CIPHERTEXT_LEN (4 bytes, big-endian unsigned int)
    CIPHERTEXT (variable length)

Nothing here is secret except the message itself (protected by the key)
and the password (never included at all). Salt, nonce, and tag are
meant to be public.
"""

import struct
from Crypto.Cipher import AES

import config
from crypto.key_derivation import derive_key, generate_salt

# Struct format for the fixed-size header fields:
#   4s  = 4-byte magic
#   B   = 1-byte version
#   16s = 16-byte salt
#   12s = 12-byte nonce
#   16s = 16-byte GCM tag
#   I   = 4-byte big-endian ciphertext length
_HEADER_FORMAT = ">4sB16s12s16sI"
_HEADER_SIZE = struct.calcsize(_HEADER_FORMAT)


def encrypt_message(message: str, password: str) -> bytes:
    """
    Encrypt a UTF-8 text message with AES-256-GCM using a password-derived
    key, and package the result into the self-contained payload format
    described above.

    Parameters
    ----------
    message : str
        The secret message to protect.
    password : str
        Password used to derive the AES key (never stored/embedded itself).

    Returns
    -------
    bytes
        The full payload (header + ciphertext) ready to be hidden in an
        image by steganography/encoder.py.
    """
    if message is None or message == "":
        raise ValueError("Message must not be empty.")

    plaintext = message.encode("utf-8")

    salt = generate_salt()
    key = derive_key(password, salt)

    cipher = AES.new(key, AES.MODE_GCM, nonce=None)  # random nonce auto-generated
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    header = struct.pack(
        _HEADER_FORMAT,
        config.MAGIC_HEADER,
        config.FORMAT_VERSION,
        salt,
        nonce,
        tag,
        len(ciphertext),
    )

    return header + ciphertext


class AuthenticationError(Exception):
    """Raised when AES-GCM tag verification fails (wrong password or
    tampered/corrupted payload)."""
    pass


class InvalidPayloadError(Exception):
    """Raised when the extracted bytes do not match our expected payload
    format (wrong magic bytes, truncated data, unsupported version, etc.)."""
    pass


def decrypt_message(payload: bytes, password: str) -> str:
    """
    Parse a payload produced by encrypt_message() and decrypt it.

    Raises
    ------
    InvalidPayloadError
        If the payload is too short, has the wrong magic bytes, an
        unsupported version, or a ciphertext-length mismatch (extraction
        pulled out something that isn't a valid payload at all).
    AuthenticationError
        If AES-GCM tag verification fails -- this means either the
        password was wrong, or the payload/image was tampered with or
        corrupted after encryption.
    """
    if len(payload) < _HEADER_SIZE:
        raise InvalidPayloadError("Payload is too short to contain a valid header.")

    magic, version, salt, nonce, tag, ct_len = struct.unpack(
        _HEADER_FORMAT, payload[:_HEADER_SIZE]
    )

    if magic != config.MAGIC_HEADER:
        raise InvalidPayloadError(
            "No valid hidden payload found (magic header mismatch)."
        )
    if version != config.FORMAT_VERSION:
        raise InvalidPayloadError(f"Unsupported payload format version: {version}.")

    ciphertext = payload[_HEADER_SIZE:_HEADER_SIZE + ct_len]
    if len(ciphertext) != ct_len:
        raise InvalidPayloadError(
            "Payload is truncated or corrupted (ciphertext length mismatch)."
        )

    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        # pycryptodome raises ValueError("MAC check failed") on bad tag
        raise AuthenticationError(
            "Authentication failed: incorrect password or corrupted/tampered payload."
        ) from exc

    return plaintext.decode("utf-8")


def get_header_size() -> int:
    """Expose header size so the steganography layer can validate capacity."""
    return _HEADER_SIZE