import os
import logging
import time
import json
import subprocess
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
import fcntl  # for file locking

app = Flask(__name__)

# Configure logging
log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=log_level, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Trivy DB settings
DB_CACHE_DIR = "/root/.cache/trivy/db"  # Update to Trivy's actual cache directory path if needed
DB_LOCK_FILE = "/tmp/trivy_db_lockfile.lock"
DB_UPDATE_INTERVAL = timedelta(minutes=30)

def clear_trivy_cache():
    """
    Clears the Trivy database cache by deleting the cache directory.
    """
    try:
        if os.path.exists(DB_CACHE_DIR):
            for root, dirs, files in os.walk(DB_CACHE_DIR, topdown=False):
                for name in files:
                    os.remove(os.path.join(root, name))
                for name in dirs:
                    os.rmdir(os.path.join(root, name))
            logger.info("Cleared Trivy database cache.")
        else:
            logger.info("Trivy database cache directory does not exist; nothing to clear.")
    except Exception as e:
        logger.error(f"Error clearing Trivy cache: {e}")

def refresh_trivy_db_if_needed():
    """
    Refreshes the Trivy DB if the cache is outdated by removing the cache files.
    """
    try:
        # Check the cache's last modification time
        if os.path.exists(DB_CACHE_DIR):
            last_modified_time = datetime.fromtimestamp(os.path.getmtime(DB_CACHE_DIR))
            if datetime.now() - last_modified_time < DB_UPDATE_INTERVAL:
                logger.info("Trivy DB cache is up-to-date.")
                return True
            else:
                logger.info("Trivy DB cache is outdated.")
        else:
            logger.info("Trivy DB cache directory not found. Will force download.")

        # Use file lock to ensure only one process clears the cache at a time
        with open(DB_LOCK_FILE, "w") as lockfile:
            fcntl.flock(lockfile, fcntl.LOCK_EX)
            clear_trivy_cache()
            fcntl.flock(lockfile, fcntl.LOCK_UN)
        return True
    except Exception as e:
        logger.error(f"Failed to refresh Trivy database: {e}")
        return False

@app.route("/scan", methods=["POST"])
def scan_image():
    data = {key.lower(): value for key, value in request.json.items()}
    image = data.get("image")
    username = data.get("username")
    password = data.get("password")

    # Log each scan request
    logger.info(f"Received scan request for image: {image}, tag: {data.get('tag')}")

    # Check if image name is provided
    if not image:
        logger.error("No image name provided in scan request")
        return jsonify({"error": "Image name is required"}), 400

    # Ensure the Trivy vulnerability database is up to date
    if not refresh_trivy_db_if_needed():
        return jsonify({"error": "Vulnerability database unavailable"}), 503

    # Base Trivy command with remote option to avoid Docker daemon dependency
    cmd = ["trivy", "-q", "-f", "json", "--scanners", "vuln", "image", image]

    # Add registry credentials to command if provided
    if username and password:
        logger.info("Using provided credentials for image registry (credentials are not exposed)")
        cmd.extend(["--username", username, "--password", password])

    # Run Trivy scan command and capture output
    start_time = time.time()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
        )
        duration = time.time() - start_time
        results_json = json.loads(result.stdout)

        # Log the scan duration and response
        logger.info(f"Scan completed in {duration:.2f} seconds for image: {image}")
       # logger.debug(f"Scan response: {json.dumps(results_json, indent=2)}")
        return jsonify(results_json)

    except subprocess.CalledProcessError as e:
        duration = time.time() - start_time
        logger.error(f"Trivy scan failed after {duration:.2f} seconds: {e.stderr}")
        return jsonify({"error": "Trivy scan failed", "details": e.stderr}), 500

if __name__ == "__main__":
    app.run(debug=True)
