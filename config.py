"""
config.py
---------
Central configuration for the Secure Image Steganography project.

Why a separate config file?
Beginner note: instead of scattering "magic numbers" and settings across
every module, we keep them in one place. This makes the project easier to
audit (important for a security project!) and easier to tune later.
"""

import os

# ---------------------------------------------------------------------------
# Filesystem paths
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
OUTPUT_FOLDER = os.path.join(BASE_DIR, "output")
RESULTS_FOLDER = os.path.join(BASE_DIR, "results")

# ---------------------------------------------------------------------------
# File validation
# ---------------------------------------------------------------------------
# Only lossless formats are allowed as COVER images. Lossy formats like JPEG
# would corrupt the hidden LSB payload during compression, so we reject them
# at upload time.
ALLOWED_COVER_EXTENSIONS = {"png", "bmp"}

# Stego images we accept for extraction. Same reasoning as above -- if a
# stego PNG has been re-saved as JPEG, extraction is not going to reliably
# succeed, so we don't pretend otherwise.
ALLOWED_STEGO_EXTENSIONS = {"png", "bmp"}

MAX_UPLOAD_SIZE_MB = 25
MAX_UPLOAD_SIZE_BYTES = MAX_UPLOAD_SIZE_MB * 1024 * 1024

# ---------------------------------------------------------------------------
# Cryptography parameters
# ---------------------------------------------------------------------------
# AES-256 -> 32-byte key
AES_KEY_LEN_BYTES = 32

# Recommended nonce length for AES-GCM
GCM_NONCE_LEN_BYTES = 12

# GCM authentication tag length
GCM_TAG_LEN_BYTES = 16

# Salt length for password-based key derivation
KDF_SALT_LEN_BYTES = 16

# scrypt cost parameters (tuned to be strong but still responsive in a demo
# web app -- a real production system handling high-value secrets might
# tune these higher and measure the resulting delay).
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1

# ---------------------------------------------------------------------------
# Steganography parameters
# ---------------------------------------------------------------------------
# How many bits of each color channel byte we use to store payload data.
# 1 = classic LSB (least detectable, lowest capacity).
# Kept configurable so the "experimental analysis" module (Step 10) can
# study the quality/capacity trade-off later if desired.
BITS_PER_CHANNEL = 1

# Embedding modes
EMBED_MODE_SEQUENTIAL = "sequential"
EMBED_MODE_RANDOM = "randomized"

# Magic bytes written at the start of every payload so the extractor can
# recognize "this PNG actually contains our payload format" before trying
# to decrypt anything.
MAGIC_HEADER = b"SIMG"
FORMAT_VERSION = 1

# ---------------------------------------------------------------------------
# Steganalysis / detectability scoring thresholds
# ---------------------------------------------------------------------------
DETECTABILITY_LOW_MAX = 30
DETECTABILITY_MEDIUM_MAX = 60
# anything above DETECTABILITY_MEDIUM_MAX is HIGH

# Flask
SECRET_KEY_ENV_VAR = "STEGO_APP_SECRET_KEY"  # set via environment, never hardcoded
DEBUG = True  # set False for any real deployment