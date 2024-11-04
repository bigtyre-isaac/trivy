from flask import Flask, request, jsonify
import subprocess
import json

app = Flask(__name__)

@app.route("/scan", methods=["POST"])
def scan_image():
    data = request.json
    data = {key.lower(): value for key, value in request.json.items()}
    image = data.get("image")
    username = data.get("username")
    password = data.get("password")

    if not image:
        return jsonify({"error": "Image name is required"}), 400

    # Base Trivy command with remote option to avoid Docker daemon dependency
    cmd = ["trivy", "-q", "-f", "json", "--scanners", "vuln", "image", image]

    # Add registry credentials to command if provided
    if username and password:
        cmd.extend(["--username", username, "--password", password])

    # Run Trivy scan command and capture output
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
        )
        results_json = json.loads(result.stdout)
        return jsonify(results_json)
    except subprocess.CalledProcessError as e:
        return jsonify({"error": "Trivy scan failed", "details": e.stderr}), 500
