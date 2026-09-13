"""
app.py
------
Entry point for the Secure Image Steganography Flask application.

This is Step 1's skeleton only: routing structure and page rendering.
The actual encryption, embedding, extraction, and analysis logic will be
wired in during Steps 2-13, imported from the crypto/, steganography/,
steganalysis/, and analysis/ packages.
"""

import os
from flask import Flask, render_template

import config

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = config.MAX_UPLOAD_SIZE_BYTES
app.secret_key = os.environ.get(config.SECRET_KEY_ENV_VAR, os.urandom(24))

# Ensure working folders exist at startup
for folder in (config.UPLOAD_FOLDER, config.OUTPUT_FOLDER, config.RESULTS_FOLDER):
    os.makedirs(folder, exist_ok=True)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/encrypt", methods=["GET"])
def encrypt_page():
    # POST handling (actual encrypt + hide logic) arrives in Step 5
    return render_template("encrypt.html")


@app.route("/decrypt", methods=["GET"])
def decrypt_page():
    # POST handling (actual extract + decrypt logic) arrives in Step 5
    return render_template("decrypt.html")


@app.route("/analysis", methods=["GET"])
def analysis_page():
    # Quality metrics, steganalysis, and graphs arrive in Steps 7-10
    return render_template("analysis.html")


@app.route("/about")
def about_page():
    return render_template("about.html")


if __name__ == "__main__":
    app.run(debug=config.DEBUG)