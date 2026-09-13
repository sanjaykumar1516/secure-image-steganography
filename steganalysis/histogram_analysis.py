"""
steganalysis/histogram_analysis.py
-------------------------------------
RGB Histogram Analysis: a "no original needed" steganalysis technique. An
analyst who only has the SUSPECT (stego) image can still compare its
color-value histogram shape against what's statistically typical for
natural photos. LSB embedding tends to subtly smooth out the histogram
(adjacent value pairs like 100/101 become more equal in frequency, since
bit-flips shuffle values between even/odd neighbors). This module
computes and compares histograms; when we DO have the original (as in
this app's own testing/experiment flow), we measure the actual shift
directly, which is the more reliable indicator we surface in the UI.
"""

import numpy as np
from PIL import Image


def compute_rgb_histograms(image: Image.Image) -> dict:
    """
    Compute a 256-bin histogram for each of the R, G, B channels.
    Returns dict of numpy arrays: {'R': [...], 'G': [...], 'B': [...]}
    """
    arr = np.array(image.convert("RGB"), dtype=np.uint8)
    histograms = {}
    for i, channel_name in enumerate(("R", "G", "B")):
        hist, _ = np.histogram(arr[:, :, i], bins=256, range=(0, 256))
        histograms[channel_name] = hist
    return histograms


def histogram_difference(original: Image.Image, stego: Image.Image) -> dict:
    """
    Compare RGB histograms of original vs stego images.

    We report:
      - per-channel total variation distance (sum of absolute bin
        differences / 2, normalized to 0-100 as a percentage of total
        pixels) -- a standard, easy-to-explain histogram distance metric.
      - an overall averaged score across channels.

    A higher score means the histograms diverged more.
    """
    orig_hist = compute_rgb_histograms(original)
    stego_hist = compute_rgb_histograms(stego)

    total_pixels = original.convert("RGB").size[0] * original.convert("RGB").size[1]

    per_channel_scores = {}
    for channel in ("R", "G", "B"):
        tv_distance = np.sum(np.abs(
            orig_hist[channel].astype(np.int64) - stego_hist[channel].astype(np.int64)
        )) / 2
        # normalize: max possible TV distance is total_pixels (if histograms
        # share zero overlap), so express as a percentage
        score = (tv_distance / total_pixels) * 100 if total_pixels else 0.0
        per_channel_scores[channel] = float(score)

    overall_score = float(np.mean(list(per_channel_scores.values())))

    return {
        "per_channel_scores": per_channel_scores,
        "overall_score": overall_score,
        "original_histograms": {k: v.tolist() for k, v in orig_hist.items()},
        "stego_histograms": {k: v.tolist() for k, v in stego_hist.items()},
    }