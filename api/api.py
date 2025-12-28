from flask import Flask, request, jsonify
import sqlite3
import subprocess
import hashlib
import os
import logging
from pathlib import Path

app = Flask(__name__)

# Secure logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_DIR = Path("/app/data").resolve()


@app.route("/auth", methods=["POST"])
def auth():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # ✅ Parameterized query (no SQL injection)
    cursor.execute(
        "SELECT 1 FROM users WHERE username=? AND password=?",
        (username, password)
    )

    result = cursor.fetchone()
    conn.close()

    if result:
        return jsonify(status="authenticated")
    return jsonify(status="denied"), 401


@app.route("/exec", methods=["POST"])
def exec_cmd():
    data = request.get_json(silent=True) or {}
    cmd = data.get("cmd")

    if not isinstance(cmd, list):
        return jsonify(error="Command must be a list"), 400

    # ✅ No shell=True
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False
    )

    return jsonify(output=result.stdout)


@app.route("/deserialize", methods=["POST"])
def deserialize():
    # ❌ Dangerous deserialization removed
    return jsonify(error="Deserialization not allowed"), 403


@app.route("/encrypt", methods=["POST"])
def encrypt():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")

    # ✅ Strong hash
    hashed = hashlib.sha256(text.encode()).hexdigest()
    return jsonify(hash=hashed)


@app.route("/file", methods=["POST"])
def read_file():
    data = request.get_json(silent=True) or {}
    filename = data.get("filename", "")

    file_path = (BASE_DIR / filename).resolve()

    # ✅ Prevent path traversal
    if not str(file_path).startswith(str(BASE_DIR)):
        return jsonify(error="Invalid file path"), 400

    if not file_path.exists():
        return jsonify(error="File not found"), 404

    return jsonify(content=file_path.read_text())


@app.route("/log", methods=["POST"])
def log_data():
    data = request.get_json(silent=True)

    # ✅ Safe logging
    logger.info("User input received")
    return jsonify(status="logged")


if __name__ == "__main__":
    # ✅ debug disabled
    app.run(host="0.0.0.0", port=5000, debug=False)
