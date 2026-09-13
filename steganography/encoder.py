"""
steganography/encoder.py
--------------------------
LSB (Least Significant Bit) embedding.

Beginner-friendly concept:
Every pixel in an RGB image has three 8-bit color channels (Red, Green,
Blue), each a number 0-255. The LAST bit of an 8-bit number barely affects
its value -- changing 200 (11001000) to 201 (11001001) is visually
imperceptible. So we can smuggle our own bits in there: for every channel
byte we want to use, we overwrite just its last bit with one bit of our
secret data, and reconstruct the secret later by reading those last bits
back in the same order.

This file treats the image as one big flat array of channel bytes:
    [R0, G0, B0, R1, G1, B1, R2, G2, B2, ...]
and embeds bits at chosen positions (indices) into that array.

Two embedding modes:
  * SEQUENTIAL — bits go into positions 0, 1, 2, 3, ... in order. Simple,
    but an attacker who suspects LSB steganography knows exactly where to
    look first.
  * RANDOMIZED — bits go into a pseudorandom subset/order of positions,
    generated from a seed derived from the password. Without the
    password, an attacker cannot know which of the millions of possible
    positions were used, which is meant to make simple statistical
    attacks somewhat harder (see steganalysis/ for how we evaluate this
    claim rather than assume it).

We always store a small, UNENCRYPTED 32-bit "payload length" header in the
first 32 positions (sequentially) regardless of mode. This only reveals
"how many bytes are hidden", never the content -- the extractor needs it
to know how many bits to read back before it can even attempt decryption.
"""

import hashlib
import struct

import numpy as np
from PIL import Image

import config


class CapacityError(Exception):
    """Raised when the payload is too large to fit in the given image."""
    pass


LENGTH_HEADER_BITS = 32  # 4-byte unsigned length prefix, always sequential


def _password_seed(password: str) -> int:
    """
    Derive a deterministic 64-bit integer seed from the password for the
    randomized embedding order. This is intentionally a *different*
    derivation (plain SHA-256 with a fixed domain-separation tag) from the
    AES key derivation in crypto/key_derivation.py -- it only needs to be
    deterministic and unpredictable without the password, not
    cryptographically resistant to brute force at the same level as the
    encryption key, since worst case an attacker who recovers embedding
    order still needs the real AES key to read anything.
    """
    if not password:
        raise ValueError("Password must not be empty.")
    digest = hashlib.sha256(password.encode("utf-8") + b"|stego-position-seed").digest()
    return int.from_bytes(digest[:8], "big")


def _bytes_to_bits(data: bytes) -> np.ndarray:
    """Convert bytes to a numpy array of individual bits (MSB first per byte)."""
    arr = np.frombuffer(data, dtype=np.uint8)
    bits = np.unpackbits(arr)
    return bits


def _bits_to_bytes(bits: np.ndarray) -> bytes:
    """Convert a numpy array of bits back into bytes."""
    # unpackbits/packbits require length to be a multiple of 8
    packed = np.packbits(bits)
    return packed.tobytes()


def calculate_capacity(image: Image.Image) -> dict:
    """
    Calculate how many payload bytes can be hidden in this image.

    Returns
    -------
    dict with:
        width, height            image dimensions
        total_channel_positions  total number of R/G/B byte positions
        usable_bits               positions available AFTER reserving the
                                   32-bit length header
        usable_bytes               usable_bits // 8 -- the real capacity
                                    for the encrypted payload
    """
    rgb = image.convert("RGB")
    width, height = rgb.size
    total_positions = width * height * 3

    usable_bits = total_positions - LENGTH_HEADER_BITS
    usable_bytes = max(usable_bits, 0) // 8

    return {
        "width": width,
        "height": height,
        "total_channel_positions": total_positions,
        "usable_bits": usable_bits,
        "usable_bytes": usable_bytes,
    }


def _randomized_positions(total_positions: int, password: str, n_bits: int) -> np.ndarray:
    """
    Generate the pseudorandom position order used for randomized embedding,
    consistent between encoder and decoder given the same password.
    """
    seed = _password_seed(password)
    rng = np.random.default_rng(seed)
    remaining = np.arange(LENGTH_HEADER_BITS, total_positions, dtype=np.int64)
    permuted = rng.permutation(remaining)
    return permuted[:n_bits]


def embed_payload(image: Image.Image, payload: bytes, mode: str = config.EMBED_MODE_SEQUENTIAL,
                   password: str | None = None) -> Image.Image:
    """
    Hide `payload` bytes inside `image` using LSB steganography.

    Parameters
    ----------
    image : PIL.Image.Image
        Cover image (converted to RGB internally; use a lossless format
        like PNG/BMP when saving the result).
    payload : bytes
        The data to hide. In this project this is always the AES-256-GCM
        encrypted payload produced by crypto.encryption.encrypt_message,
        never plaintext.
    mode : str
        config.EMBED_MODE_SEQUENTIAL or config.EMBED_MODE_RANDOM.
    password : str, optional
        Required when mode == EMBED_MODE_RANDOM, used to derive the
        embedding position order (NOT the same derivation as the AES key).

    Returns
    -------
    PIL.Image.Image
        The stego image. Caller is responsible for saving it losslessly.
    """
    if mode == config.EMBED_MODE_RANDOM and not password:
        raise ValueError("Randomized embedding requires a password to derive position order.")

    rgb = image.convert("RGB")
    arr = np.array(rgb, dtype=np.uint8)
    h, w, c = arr.shape
    flat = arr.reshape(-1).copy()
    total_positions = flat.size

    capacity = calculate_capacity(rgb)
    payload_bits_len = len(payload) * 8

    if payload_bits_len > capacity["usable_bits"]:
        raise CapacityError(
            f"Payload requires {payload_bits_len} bits but only "
            f"{capacity['usable_bits']} bits are available in this image."
        )

    # 1) Embed the 32-bit length header sequentially in positions [0, 32)
    length_bytes = struct.pack(">I", len(payload))
    length_bits = _bytes_to_bits(length_bytes)  # 32 bits
    flat[:LENGTH_HEADER_BITS] = (flat[:LENGTH_HEADER_BITS] & ~np.uint8(1)) | length_bits

    # 2) Determine positions for the payload itself
    if mode == config.EMBED_MODE_SEQUENTIAL:
        positions = np.arange(LENGTH_HEADER_BITS, LENGTH_HEADER_BITS + payload_bits_len, dtype=np.int64)
    elif mode == config.EMBED_MODE_RANDOM:
        positions = _randomized_positions(total_positions, password, payload_bits_len)
    else:
        raise ValueError(f"Unknown embedding mode: {mode}")

    payload_bits = _bytes_to_bits(payload)
    flat[positions] = (flat[positions] & ~np.uint8(1)) | payload_bits

    stego_arr = flat.reshape(h, w, c)
    return Image.fromarray(stego_arr, "RGB")


def get_modified_positions(image_shape: tuple, payload_len_bytes: int, mode: str,
                            password: str | None = None) -> np.ndarray:
    """
    Utility for the steganalysis/experiments modules: recompute exactly
    which flat channel-array positions were touched during embedding
    (length header + payload), without re-running embedding. Useful for
    building "ground truth" masks, e.g. for the block-level ML detector.
    """
    h, w, c = image_shape
    total_positions = h * w * c
    payload_bits_len = payload_len_bytes * 8

    header_positions = np.arange(0, LENGTH_HEADER_BITS, dtype=np.int64)

    if mode == config.EMBED_MODE_SEQUENTIAL:
        payload_positions = np.arange(
            LENGTH_HEADER_BITS, LENGTH_HEADER_BITS + payload_bits_len, dtype=np.int64
        )
    elif mode == config.EMBED_MODE_RANDOM:
        payload_positions = _randomized_positions(total_positions, password, payload_bits_len)
    else:
        raise ValueError(f"Unknown embedding mode: {mode}")

    return np.concatenate([header_positions, payload_positions])