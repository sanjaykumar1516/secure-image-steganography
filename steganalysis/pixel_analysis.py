"""
analysis/image_metrics.py
---------------------------
Objective image-quality comparison between the original cover image and
the generated stego image.

Beginner-friendly concept:

MSE (Mean Squared Error): average of the squared per-channel differences
between the two images. Lower = more similar. 0 means pixel-identical.

PSNR (Peak Signal-to-Noise Ratio, in decibels): derived from MSE, but
expressed on a scale where HIGHER = more similar (the usual convention in
image-quality literature). For 8-bit images:

    PSNR = 20 * log10(255 / sqrt(MSE))

PSNR above ~40 dB is generally considered visually indistinguishable from
the original; LSB steganography with only 1 bit per channel typically
produces PSNR well above 50 dB even for large payloads, because each
changed byte moves by at most 1 out of 255.
"""

import numpy as np
from PIL import Image


class ImageSizeMismatchError(Exception):
    """Raised when comparing two images of different dimensions."""
    pass


def compute_metrics(original: Image.Image, stego: Image.Image) -> dict:
    """
    Compute MSE, PSNR, and modified-pixel statistics between the original
    cover image and the stego image produced from it.

    Returns
    -------
    dict with keys:
        mse                     float
        psnr_db                 float ('inf' as a string if images are identical)
        modified_pixels         int   -- pixels where ANY channel differs
        total_pixels            int
        modified_pixel_percent  float
        avg_pixel_diff          float -- mean absolute difference, all channels
        max_pixel_diff          int   -- largest single-channel absolute difference
    """
    orig_rgb = original.convert("RGB")
    stego_rgb = stego.convert("RGB")

    if orig_rgb.size != stego_rgb.size:
        raise ImageSizeMismatchError(
            f"Cannot compare images of different sizes: "
            f"{orig_rgb.size} vs {stego_rgb.size}"
        )

    orig_arr = np.array(orig_rgb, dtype=np.float64)
    stego_arr = np.array(stego_rgb, dtype=np.float64)

    diff = orig_arr - stego_arr
    abs_diff = np.abs(diff)

    mse = float(np.mean(diff ** 2))

    if mse == 0.0:
        psnr_db = float("inf")
    else:
        psnr_db = float(20 * np.log10(255.0 / np.sqrt(mse)))

    # A pixel counts as "modified" if ANY of its R/G/B channels changed
    per_pixel_changed = np.any(abs_diff > 0, axis=2)
    modified_pixels = int(np.sum(per_pixel_changed))
    total_pixels = int(orig_rgb.size[0] * orig_rgb.size[1])
    modified_pixel_percent = (modified_pixels / total_pixels) * 100 if total_pixels else 0.0

    avg_pixel_diff = float(np.mean(abs_diff))
    max_pixel_diff = int(np.max(abs_diff))

    return {
        "mse": mse,
        "psnr_db": psnr_db,
        "modified_pixels": modified_pixels,
        "total_pixels": total_pixels,
        "modified_pixel_percent": modified_pixel_percent,
        "avg_pixel_diff": avg_pixel_diff,
        "max_pixel_diff": max_pixel_diff,
    }


def compute_payload_usage(usable_bytes: int, payload_bytes: int) -> dict:
    """
    Payload capacity usage, as specified in the project brief:
        Payload Usage % = (Encrypted Payload Size / Available Capacity) * 100
    """
    if usable_bytes <= 0:
        percent = 0.0
    else:
        percent = (payload_bytes / usable_bytes) * 100

    return {
        "usable_bytes": usable_bytes,
        "payload_bytes": payload_bytes,
        "remaining_bytes": max(usable_bytes - payload_bytes, 0),
        "usage_percent": percent,
    }