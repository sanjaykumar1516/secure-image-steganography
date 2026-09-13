"""
steganography/decoder.py
--------------------------
LSB extraction -- the reverse of steganography/encoder.py.

The extractor doesn't know the payload's length in advance, which is why
the encoder always writes a 32-bit length header (sequentially, in the
first 32 channel-byte positions) before the payload itself. We read that
header first, then read exactly that many bits back using the same
position order (sequential or password-derived randomized) that the
encoder used.
"""

import struct

import numpy as np
from PIL import Image

import config
from steganography.encoder import (
    LENGTH_HEADER_BITS,
    _bits_to_bytes,
    _randomized_positions,
)


class ExtractionError(Exception):
    """Raised when the stego image does not contain a plausible payload
    (e.g. declared length exceeds available capacity) -- this catches
    "wrong image" / "no hidden data" / "corrupted" cases at the
    steganography layer, BEFORE the crypto layer even attempts to
    decrypt anything."""
    pass


def _read_length_header(flat: np.ndarray) -> int:
    header_bits = flat[:LENGTH_HEADER_BITS] & 1
    header_bytes = _bits_to_bytes(header_bits)
    (length,) = struct.unpack(">I", header_bytes)
    return length


def extract_payload(image: Image.Image, mode: str = config.EMBED_MODE_SEQUENTIAL,
                     password: str | None = None) -> bytes:
    """
    Extract the hidden payload bytes from a stego image.

    Parameters
    ----------
    image : PIL.Image.Image
        The stego image (must be opened from a lossless file -- if it was
        re-saved as JPEG at any point, extraction will not work reliably).
    mode : str
        Must match the mode used during embedding.
    password : str, optional
        Required when mode == EMBED_MODE_RANDOM, to regenerate the same
        position order used at embed time.

    Returns
    -------
    bytes
        The raw payload bytes (still encrypted -- decrypt with
        crypto.encryption.decrypt_message).

    Raises
    ------
    ExtractionError
        If the declared payload length is implausible for this image
        (almost certainly means "wrong image", "wrong mode", or
        "corrupted/not a stego image at all").
    """
    if mode == config.EMBED_MODE_RANDOM and not password:
        raise ValueError("Randomized extraction requires a password to derive position order.")

    rgb = image.convert("RGB")
    arr = np.array(rgb, dtype=np.uint8)
    h, w, c = arr.shape
    flat = arr.reshape(-1)
    total_positions = flat.size

    if total_positions <= LENGTH_HEADER_BITS:
        raise ExtractionError("Image is too small to contain a valid header.")

    length = _read_length_header(flat)
    payload_bits_len = length * 8

    max_possible_bits = total_positions - LENGTH_HEADER_BITS
    if length == 0:
        raise ExtractionError("No hidden payload detected (declared length is zero).")
    if payload_bits_len > max_possible_bits:
        raise ExtractionError(
            "No valid hidden payload detected for this mode/password "
            "(declared length exceeds image capacity -- likely wrong "
            "image, wrong embedding mode, or wrong password)."
        )

    if mode == config.EMBED_MODE_SEQUENTIAL:
        positions = np.arange(LENGTH_HEADER_BITS, LENGTH_HEADER_BITS + payload_bits_len, dtype=np.int64)
    elif mode == config.EMBED_MODE_RANDOM:
        positions = _randomized_positions(total_positions, password, payload_bits_len)
    else:
        raise ValueError(f"Unknown embedding mode: {mode}")

    bits = flat[positions] & 1
    payload = _bits_to_bytes(bits)
    return payload