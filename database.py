"""
database.py
-----------
Firebase Realtime Database REST API Client.
Handles connection session retries, timeouts, and fallbacks.
"""

import os
import logging
from datetime import datetime, timezone
import requests as _requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DatabaseClient")

# --- Configuration ---
FIREBASE_DATABASE_URL = os.environ.get("FIREBASE_DATABASE_URL", "").rstrip("/").strip()
FIREBASE_DATABASE_SECRET = os.environ.get("FIREBASE_DATABASE_SECRET", "").strip()

if not FIREBASE_DATABASE_URL:
    raise EnvironmentError(
        "FIREBASE_DATABASE_URL environment variable is missing.\n"
        "Please configure your default Realtime Database URL."
    )

# Establish a resilient connection pool to handle API communication
_session = _requests.Session()
_retries = Retry(
    total=5,  # Increased to 5 retries for high availability
    backoff_factor=0.5,
    status_forcelist=[429, 500, 502, 503, 504],
    raise_on_status=False
)
_session.mount("https://", HTTPAdapter(max_retries=_retries, pool_connections=10, pool_maxsize=100))
_session.mount("http://", HTTPAdapter(max_retries=_retries, pool_connections=10, pool_maxsize=100))


# --- Internal Network Helpers ---

def _url(path: str) -> str:
    """Formats the requested database endpoint."""
    return f"{FIREBASE_DATABASE_URL}/{path.strip('/')}.json"


def _params() -> dict:
    """Returns credential params if a database secret is configured."""
    if FIREBASE_DATABASE_SECRET:
        return {"auth": FIREBASE_DATABASE_SECRET}
    return {}


def _handle_response(response: _requests.Response) -> any:
    """Validates HTTP responses and raises clean, descriptive errors."""
    try:
        response.raise_for_status()
    except _requests.HTTPError as error:
        logger.error(f"Firebase REST query returned a failure: {response.status_code} - {response.text}")
        raise RuntimeError(
            f"Database communication failure (Status {response.status_code}): {response.text[:300]}"
        ) from error
    
    try:
        return response.json()
    except ValueError:
        return None


# --- Public Core CRUD Engine ---

def fb_get(path: str) -> any:
    """Performs a GET request. Returns parsed JSON or None if the path is empty."""
    try:
        response = _session.get(_url(path), params=_params(), timeout=12)
        return _handle_response(response)
    except Exception as e:
        logger.error(f"Failed to execute GET request on path '/{path}': {e}")
        return None


def fb_set(path: str, data: any) -> None:
    """Performs a PUT request, overwriting the database path completely."""
    try:
        response = _session.put(_url(path), json=data, params=_params(), timeout=12)
        _handle_response(response)
    except Exception as e:
        logger.error(f"Failed to execute SET request on path '/{path}': {e}")
        raise


def fb_update(path: str, data: dict) -> None:
    """Performs a PATCH request, modifying only the fields specified in the dict."""
    try:
        response = _session.patch(_url(path), json=data, params=_params(), timeout=12)
        _handle_response(response)
    except Exception as e:
        logger.error(f"Failed to execute UPDATE request on path '/{path}': {e}")
        raise


def fb_delete(path: str) -> None:
    """Performs a DELETE request, purging the node completely."""
    try:
        response = _session.delete(_url(path), params=_params(), timeout=12)
        _handle_response(response)
    except Exception as e:
        logger.error(f"Failed to execute DELETE request on path '/{path}': {e}")
        raise


# --- Unified Feature Extensions ---

def add_fsub_channel(chat_id: str, invite_link: str, button_name: str) -> None:
    """Registers Force Join configurations inside the Firebase database."""
    try:
        fb_set(f"/force_join/{chat_id}", {
            "invite_link": invite_link,
            "button_name": button_name,
            "created_at": datetime.now(timezone.utc).isoformat()
        })
        logger.info(f"Force Join configuration saved for Chat ID: {chat_id}")
    except Exception as e:
        logger.error(f"Database write execution failed in add_fsub_channel: {e}")
        raise


def remove_fsub_channel(chat_id: str) -> bool:
    """Removes a configured Force Join channel from the database."""
    try:
        if fb_get(f"/force_join/{chat_id}"):
            fb_delete(f"/force_join/{chat_id}")
            logger.info(f"Force Join configuration purged for Chat ID: {chat_id}")
            return True
        return False
    except Exception as e:
        logger.error(f"Database write execution failed in remove_fsub_channel: {e}")
        return False


def get_fsub_channels() -> dict:
    """Fetches all registered Force Join channel mappings."""
    data = fb_get("/force_join")
    return data if isinstance(data, dict) else {}


def save_project_metadata(file_id: str, project_name: str, output_name: str) -> None:
    """Attaches identification parameters to an encrypted file signature."""
    try:
        fb_update(f"/files/{file_id}", {
            "project_name": project_name,
            "output_name": output_name
        })
        logger.info(f"Successfully pinned project metadata for File ID: {file_id}")
    except Exception as e:
        logger.error(f"Database update execution failed in save_project_metadata: {e}")
        raise


def update_request_status(req_id: str, status: str) -> None:
    """Updates key approval or rejection milestones for an active request."""
    try:
        fb_update(f"/requests/{req_id}", {
            "status": status,
            "processed_at": datetime.now(timezone.utc).isoformat()
        })
        logger.info(f"Key authorization request '{req_id}' updated to status: {status}")
    except Exception as e:
        logger.error(f"Database update execution failed in update_request_status: {e}")
        raise


def init_firebase() -> None:
    """Validates remote database handshake connectivity."""
    auth_mode = "Secret Token Authentication" if FIREBASE_DATABASE_SECRET else "Public/No Authentication"
    logger.info(f"Connecting to database endpoint (Mode: {auth_mode})...")
    try:
        default_val = fb_get("/settings/default_limit")
        if default_val is None:
            fb_set("/settings/default_limit", 5)
            logger.info("Successfully established connection and seeded default limit value.")
        else:
            logger.info(f"Connection verification succeeded. Current default limit setting: {default_val}")
    except Exception as e:
        raise RuntimeError(f"Handshake connection test failed: {e}") from e