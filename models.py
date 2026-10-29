"""
models.py
---------
Firebase RTDB CRUD helpers using the REST client in database.py.
Handles timezone alignments, type safety, and safe error fallbacks.

Schema Rules:
  /settings/default_limit          -> int
  /users/{telegram_id}
    telegram_id                    -> int
    daily_limit                    -> int
    files_encrypted_today          -> int
    last_upload_date               -> str  (YYYY-MM-DD, IST)
  /files/{file_id}
    telegram_id                    -> int
    decryption_key                 -> str
    created_at                     -> str  (ISO datetime, IST)
    project_name                   -> str  (Optional metadata, max 20 words)
    output_name                    -> str  (Optional metadata, max 15 words)
  /banned/{user_id}
    user_id                        -> int
    banned_at                      -> str  (YYYY-MM-DD, IST)
  /requests/{req_id}
    req_id                         -> str  (Unique request ID)
    file_id                        -> str  (Associated file ID)
    owner_id                       -> int  (Telegram ID of file owner)
    project_name                   -> str  (Project Name of file)
    status                         -> str  (pending, approved, rejected, expired, cancelled)
    created_at                     -> str  (ISO datetime, IST)
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any

from database import (
    fb_get, fb_set, fb_update, fb_delete
)

logger = logging.getLogger("DatabaseModels")

# Indian Standard Time (IST) Offset Helper (UTC +5:30)
IST = timezone(timedelta(hours=5, minutes=30))


# --- Utility Time Functions ---

def today_utc() -> str:
    """Returns today's date in IST formatted as string (YYYY-MM-DD)."""
    return datetime.now(IST).date().isoformat()


def now_utc() -> str:
    """Returns current date-time in IST formatted as an ISO string."""
    return datetime.now(IST).isoformat()


# --- Settings CRUD ---

def get_default_limit() -> int:
    """Fetches global default daily limit parameter from settings node."""
    try:
        val = fb_get("/settings/default_limit")
        return int(val) if isinstance(val, (int, float)) else 5
    except Exception as e:
        logger.error(f"Error reading system default limit parameter: {e}")
        return 5


def set_default_limit(limit: int) -> None:
    """Updates the global system default encryption limit."""
    try:
        fb_set("/settings/default_limit", limit)
        logger.info(f"Global default limit adjusted to: {limit}")
    except Exception as e:
        logger.error(f"Error updating global default limit: {e}")


# --- User Management CRUD ---

def get_user(telegram_id: int) -> Optional[Dict[str, Any]]:
    """Retrieves a single user registry profile by unique Telegram ID."""
    try:
        data = fb_get(f"/users/{telegram_id}")
        return data if isinstance(data, dict) else None
    except Exception as e:
        logger.error(f"Error fetching user data profile for ID {telegram_id}: {e}")
        return None


def create_user(telegram_id: int, daily_limit: int = 5) -> Dict[str, Any]:
    """Registers a fresh user metadata record in the database."""
    data = {
        "telegram_id": telegram_id,
        "daily_limit": daily_limit,
        "files_encrypted_today": 0,
        "last_upload_date": today_utc(),
        "created_at": now_utc()
    }
    try:
        fb_set(f"/users/{telegram_id}", data)
        logger.info(f"Registered user profile for ID: {telegram_id}")
    except Exception as e:
        logger.error(f"Failed to write user profile node for ID {telegram_id}: {e}")
    return data


def update_user(telegram_id: int, updates: Dict[str, Any]) -> bool:
    """Partially updates elements inside the user database node."""
    try:
        fb_update(f"/users/{telegram_id}", updates)
        return True
    except Exception as e:
        logger.error(f"Failed updating metadata parameters for user {telegram_id}: {e}")
        return False


def get_or_create_user(telegram_id: int) -> Dict[str, Any]:
    """Retrieves a user profile. If user is absent, registers them first."""
    user = get_user(telegram_id)
    if user is None:
        user = create_user(telegram_id, daily_limit=get_default_limit())
    return user


def reset_daily_counter_if_needed(user: Dict[str, Any]) -> Dict[str, Any]:
    """Cycles and resets daily limits if server date is different from last usage date."""
    today = today_utc()
    if user.get("last_upload_date") != today:
        tid = user["telegram_id"]
        updates = {"files_encrypted_today": 0, "last_upload_date": today}
        update_user(tid, updates)
        user = {**user, **updates}
        logger.info(f"Daily encryption quota reset completed for user ID: {tid}")
    return user


def increment_user_counter(telegram_id: int) -> int:
    """Increments the counter of files encrypted by the user today by 1."""
    try:
        user = get_user(telegram_id)
        if not user:
            return 1
        new_count = int(user.get("files_encrypted_today", 0)) + 1
        fb_update(f"/users/{telegram_id}", {"files_encrypted_today": new_count})
        return new_count
    except Exception as e:
        logger.error(f"Failed incrementing database usage registers for user {telegram_id}: {e}")
        return 0


def count_user_files(telegram_id: int) -> int:
    """Calculates historical encryption output count for a single user."""
    try:
        all_files = fb_get("/files")
        if not isinstance(all_files, dict):
            return 0
        return sum(
            1 for v in all_files.values()
            if isinstance(v, dict) and str(v.get("telegram_id", "")) == str(telegram_id)
        )
    except Exception as e:
        logger.error(f"Error aggregating file index counts for {telegram_id}: {e}")
        return 0


# --- Encryption Files Licenses CRUD ---

def save_file(file_id: str, telegram_id: int, decryption_key: str) -> bool:
    """Saves generated unique license parameters and encryption keys."""
    try:
        fb_set(f"/files/{file_id}", {
            "telegram_id": telegram_id,
            "decryption_key": decryption_key,
            "created_at": now_utc(),
            "status": "active"
        })
        return True
    except Exception as e:
        logger.error(f"Failed registering file license ID {file_id}: {e}")
        return False


def get_file(file_id: str) -> Optional[Dict[str, Any]]:
    """Fetches dynamic file metadata by key reference ID."""
    try:
        data = fb_get(f"/files/{file_id}")
        return data if isinstance(data, dict) else None
    except Exception as e:
        logger.error(f"Failed retrieving license metadata for {file_id}: {e}")
        return None


def get_file_key(file_id: str) -> Optional[str]:
    """Helper method directly retrieving a file's decryption key."""
    try:
        file_data = get_file(file_id)
        if file_data:
            return file_data.get("decryption_key")
        return None
    except Exception as e:
        logger.error(f"Failed to lookup decryption signature on {file_id}: {e}")
        return None


def delete_file(file_id: str) -> bool:
    """Purges a license and key node permanently from Firebase."""
    try:
        fb_delete(f"/files/{file_id}")
        logger.info(f"License ID {file_id} successfully purged.")
        return True
    except Exception as e:
        logger.error(f"Error purging database records for file {file_id}: {e}")
        return False


# --- Bulk Directory Parsers ---

def get_all_user_ids() -> List[int]:
    """Retrieves all registered active user IDs inside a mapped list."""
    try:
        all_users = fb_get("/users")
        if not isinstance(all_users, dict):
            return []
        ids = []
        for uid in all_users.keys():
            try:
                ids.append(int(uid))
            except (ValueError, TypeError):
                pass
        return ids
    except Exception as e:
        logger.error(f"Error extracting target user directory: {e}")
        return []


def get_all_users_data() -> List[Dict[str, Any]]:
    """Retrieves detailed profile lists for administrative overview."""
    try:
        all_users = fb_get("/users")
        if not isinstance(all_users, dict):
            return []
        users = []
        for uid, data in all_users.items():
            if isinstance(data, dict):
                users.append({
                    'id': int(uid),
                    'username': data.get('username', 'Unknown'),
                    'daily_limit': data.get('daily_limit', 5),
                    'files_encrypted_today': data.get('files_encrypted_today', 0)
                })
        return users
    except Exception as e:
        logger.error(f"Error parsing user index telemetry arrays: {e}")
        return []


# --- Suspension (Ban) Administration ---

def is_user_banned(telegram_id: int) -> bool:
    """Evaluates if the profile reference is mapped in the banned database nodes."""
    try:
        banned_data = fb_get(f"/banned/{telegram_id}")
        return banned_data is not None
    except Exception as e:
        logger.error(f"Error validating system suspension context for user {telegram_id}: {e}")
        return False


def ban_user(telegram_id: int, name: str = "") -> bool:
    """Suspends target user account and logs tracking elements."""
    try:
        fb_set(f"/banned/{telegram_id}", {
            "user_id": telegram_id,
            "name": name,
            "banned_at": today_utc()
        })
        logger.info(f"Suspension flag registered for user: {telegram_id}")
        return True
    except Exception as e:
        logger.error(f"Failed to record suspension limits for {telegram_id}: {e}")
        return False


def unban_user(telegram_id: int) -> bool:
    """Removes banned profiles from active suspension directory."""
    try:
        fb_delete(f"/banned/{telegram_id}")
        logger.info(f"Suspension lifted for user: {telegram_id}")
        return True
    except Exception as e:
        logger.error(f"Failed removing suspension markers for user {telegram_id}: {e}")
        return False


def get_banned_users_list() -> List[Dict[str, Any]]:
    """Fetches array details of all currently blacklisted users safely."""
    try:
        all_banned = fb_get("/banned")
        if not isinstance(all_banned, dict):
            return []
        users = []
        for uid, data in all_banned.items():
            if isinstance(data, dict):
                users.append({
                    'id': uid,
                    'name': data.get('name', 'Unknown'),
                    'banned_at': data.get('banned_at', 'Unknown')
                })
            else:
                users.append({
                    'id': uid,
                    'name': str(data),
                    'banned_at': 'Unknown'
                })
        return users
    except Exception as e:
        logger.error(f"Failed compiling banned records telemetry: {e}")
        return []


def get_total_banned() -> int:
    """Collects total active blacklist count."""
    try:
        all_banned = fb_get("/banned")
        return len(all_banned) if isinstance(all_banned, dict) else 0
    except Exception as e:
        logger.error(f"Error measuring ban registers sizes: {e}")
        return 0

get_total_banned_count = get_total_banned  # Compatibility wrapper


# --- Aggregated Telemetry Statistics ---

def get_total_users() -> int:
    """Returns total volume of registered users in database."""
    try:
        all_users = fb_get("/users")
        return len(all_users) if isinstance(all_users, dict) else 0
    except Exception as e:
        logger.error(f"Error parsing database profiles index size: {e}")
        return 0


def get_total_encrypted_files() -> int:
    """Returns absolute sum size of stored active file licenses."""
    try:
        all_files = fb_get("/files")
        return len(all_files) if isinstance(all_files, dict) else 0
    except Exception as e:
        logger.error(f"Error parsing database files registry size: {e}")
        return 0


def get_today_activity() -> int:
    """Aggregates total files encrypted today in the IST timezone."""
    try:
        today = today_utc()
        all_users = fb_get("/users")
        if not isinstance(all_users, dict):
            return 0
        total = 0
        for uid, data in all_users.items():
            if isinstance(data, dict) and data.get("last_upload_date") == today:
                total += data.get("files_encrypted_today", 0)
        return total
    except Exception as e:
        logger.error(f"Error parsing today's dynamic encryption activities: {e}")
        return 0


def get_user_stats(telegram_id: int) -> Dict[str, Any]:
    """Extracts custom user statistics for user dashboards."""
    try:
        user = get_user(telegram_id)
        if not user:
            return {
                'exists': False,
                'message': 'User profile records missing'
            }
        
        total_files = count_user_files(telegram_id)
        remaining = max(0, user.get('daily_limit', 5) - user.get('files_encrypted_today', 0))
        
        return {
            'exists': True,
            'telegram_id': telegram_id,
            'daily_limit': user.get('daily_limit', 5),
            'files_encrypted_today': user.get('files_encrypted_today', 0),
            'total_files': total_files,
            'remaining': remaining,
            'last_upload_date': user.get('last_upload_date', 'Never'),
            'created_at': user.get('created_at', 'Unknown')
        }
    except Exception as e:
        logger.error(f"Error parsing statistical profile array for {telegram_id}: {e}")
        return {
            'exists': False,
            'message': 'Dynamic lookup telemetry error'
        }


# --- System Admin Commands Engine ---

def set_user_limit(telegram_id: int, new_limit: int) -> bool:
    """Sets custom operational daily limit ceiling directly on target profile."""
    try:
        user = get_user(telegram_id)
        if not user:
            return False
        update_user(telegram_id, {"daily_limit": new_limit})
        return True
    except Exception as e:
        logger.error(f"Failed writing custom limits variables to ID {telegram_id}: {e}")
        return False


def reset_user_counter(telegram_id: int) -> bool:
    """Manually resets the user encryption count parameters immediately."""
    try:
        update_user(telegram_id, {
            "files_encrypted_today": 0,
            "last_upload_date": today_utc()
        })
        return True
    except Exception as e:
        logger.error(f"Failed manually executing count reset parameters for {telegram_id}: {e}")
        return False


def get_all_files() -> Dict[str, Any]:
    """Retrieves full file registry dictionary elements securely."""
    try:
        return fb_get("/files") or {}
    except Exception as e:
        logger.error(f"Error fetching cumulative files catalog dictionary: {e}")
        return {}


def get_user_files(telegram_id: int) -> List[Dict[str, Any]]:
    """Gathers lists of all active file licenses belonging to a user."""
    try:
        all_files = fb_get("/files")
        if not isinstance(all_files, dict):
            return []
        user_files = []
        for file_id, data in all_files.items():
            if isinstance(data, dict) and str(data.get("telegram_id", "")) == str(telegram_id):
                user_files.append({
                    'file_id': file_id,
                    'created_at': data.get('created_at', 'Unknown'),
                    'status': data.get('status', 'active')
                })
        return user_files
    except Exception as e:
        logger.error(f"Failed extracting relative file directory structures for {telegram_id}: {e}")
        return []