"""
bot.py
------
Aiogram-based Telegram bot for code encryption and licensing.
Configured with REST-based client queries and secret 10-minute console logging flushes.
Integrated with Flask Web Server (/health 200 OK) for Render 24/7 uptime.
"""

import os
import sys
import uuid
import base64
import logging
import asyncio
import zipfile
import io
import re
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple, Any
from threading import Thread

# Load Environment Variables Safely
from dotenv import load_dotenv
load_dotenv()

# Flask HTTP Web Server for Render Health Checks
from flask import Flask, jsonify

from aiogram import Bot, Dispatcher, F, BaseMiddleware
from aiogram.filters import Command
from aiogram.types import (
    Message, BufferedInputFile, InlineKeyboardMarkup, 
    InlineKeyboardButton, CallbackQuery, LinkPreviewOptions,
    TelegramObject
)
from aiogram.fsm.state import StatesGroup, State
from aiogram.fsm.context import FSMContext
from aiogram.exceptions import TelegramAPIError
from cryptography.fernet import Fernet

from database import (
    init_firebase, fb_get, fb_set, fb_update, fb_delete,
    add_fsub_channel, remove_fsub_channel, get_fsub_channels,
    save_project_metadata, update_request_status
)
from models import (
    get_or_create_user, reset_daily_counter_if_needed,
    increment_user_counter, update_user, get_user,
    save_file, count_user_files, delete_file, get_file,
    get_default_limit, set_default_limit, get_all_user_ids,
    today_utc, is_user_banned, ban_user, unban_user,
    get_banned_users_list, get_total_users, get_total_encrypted_files,
    get_today_activity
)

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("CodeProtectorBot")

# --- Configuration ---
BOT_TOKEN = os.environ.get("BOT_TOKEN", "").strip()
API_SERVER_URL = os.environ.get("API_SERVER_URL", "").rstrip("/").strip()

if not API_SERVER_URL:
    logger.warning("API_SERVER_URL environment variable is missing. Falling back to default localhost loopback.")
    API_SERVER_URL = "http://127.0.0.1:8000"

ADMIN_ID_ENV = os.environ.get("ADMIN_ID", "").strip()
try:
    ADMIN_ID = int(ADMIN_ID_ENV)
except ValueError:
    ADMIN_ID = 0  # not configured
IST = timezone(timedelta(hours=5, minutes=30))
MAX_PY_SIZE  = 1_048_576  # 1 MB
MAX_ZIP_SIZE = 5_242_880  # 5 MB

if not BOT_TOKEN:
    logger.critical("BOT_TOKEN is missing! The service cannot start without a bot token.")
    sys.exit(1)

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()


# --- Render Health Server Setup (Flask) ---

web_app = Flask(__name__)

@web_app.route('/')
def home():
    return "CodeProtectorBot is Running!", 200

@web_app.route('/health', methods=['GET'])
def health_check():
    """Endpoint returning 200 OK for UptimeRobot / Cron-Job.org pings."""
    return jsonify({"status": "healthy", "code": 200}), 200

def run_web_server():
    port = int(os.environ.get("PORT", 8080))
    web_app.run(host="0.0.0.0", port=port)

def keep_alive():
    """Starts Flask web server in a daemon thread."""
    t = Thread(target=run_web_server)
    t.daemon = True
    t.start()
    logger.info("Flask Health Server started on port $PORT.")


# --- FSM States for Interactive Flows ---

class EncryptState(StatesGroup):
    waiting_for_admin_choice = State()  # For developer file evaluation
    waiting_for_project_name = State()  # Project details step
    waiting_for_output_name  = State()  # Named loader step
    waiting_for_env          = State()  # Custom environment setups (.env)


# --- Force Join (FSub) Outer Middleware ---

class ForceJoinMiddleware(BaseMiddleware):
    async def __call__(
        self,
        handler,
        event: TelegramObject,
        data: Dict[str, Any]
    ):
        user = None
        if isinstance(event, Message):
            user = event.from_user
            text = event.text or ""
            # Bypass validation checks on core command triggers
            if text.startswith(("/start", "/help", "/add", "/remove", "/list")):
                return await handler(event, data)
        elif isinstance(event, CallbackQuery):
            user = event.from_user
            if event.data and event.data.startswith("check_join"):
                return await handler(event, data)

        if not user:
            return await handler(event, data)

        user_id = user.id

        # Developer accounts bypass FSub checks
        if user_id == ADMIN_ID:
            return await handler(event, data)

        # Check banned statuses
        if await check_banned(user_id):
            if isinstance(event, Message):
                await event.answer("🚫 *Your usage token has been blacklisted from our services.*", parse_mode="Markdown")
            elif isinstance(event, CallbackQuery):
                await event.answer("🚫 Operational clearance revoked. Banned account profile.", show_alert=True)
            return

        channels = get_fsub_channels()
        if not channels:
            return await handler(event, data)

        not_joined = []
        for chat_id, ch_data in channels.items():
            try:
                target_chat = int(chat_id) if chat_id.startswith("-100") or chat_id.isdigit() else chat_id
                member = await event.bot.get_chat_member(target_chat, user_id)
                if member.status not in ["member", "administrator", "creator"]:
                    not_joined.append((chat_id, ch_data))
            except TelegramAPIError as e:
                logger.warning(f"Verification of user {user_id} on channel {chat_id} skipped: {e}")
                continue
            except ValueError:
                continue

        if not_joined:
            keyboard_buttons = []
            for _, ch_data in not_joined:
                keyboard_buttons.append([
                    InlineKeyboardButton(text=ch_data["button_name"], url=ch_data["invite_link"])
                ])
            
            keyboard_buttons.append([
                InlineKeyboardButton(text="🔄 Verification Complete", callback_data="check_join_status")
            ])
            
            markup = InlineKeyboardMarkup(inline_keyboard=keyboard_buttons)
            alert_text = (
                "📢 *ACCESS RESTRICTED!*\n\n"
                "Please subscribe to our verified channels to continue using this service.\n"
                "Once joined, tap the verification button below."
            )
            
            if isinstance(event, Message):
                await event.answer(alert_text, parse_mode="Markdown", reply_markup=markup)
            elif isinstance(event, CallbackQuery):
                await event.message.answer(alert_text, parse_mode="Markdown", reply_markup=markup)
                await event.answer("Channel subscription check required!", show_alert=True)
            return

        return await handler(event, data)


# --- Helper Utility Functions ---

async def check_banned(user_id: int) -> bool:
    """Verifies user ban status."""
    try:
        return is_user_banned(user_id)
    except Exception as e:
        logger.error(f"Failed to query user ban details: {e}")
        return False


def get_reset_time() -> str:
    """Calculates time remaining until the daily quota reset (00:00 IST)."""
    now = datetime.now(IST)
    tomorrow = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
    diff = tomorrow - now
    hours = diff.seconds // 3600
    minutes = (diff.seconds % 3600) // 60
    return f"{hours}h {minutes}m"


def get_total_banned_count() -> int:
    """Calculates total blacklisted users in database safely."""
    try:
        banned = get_banned_users_list()
        if isinstance(banned, (list, dict)):
            return len(banned)
        return 0
    except Exception:
        return 0


def restructure_and_strip_env(zip_bytes: bytes) -> bytes:
    """Excludes loose metadata levels and strips pre-existing .env references."""
    try:
        in_file = io.BytesIO(zip_bytes)
        with zipfile.ZipFile(in_file, 'r') as z_in:
            namelist = z_in.namelist()
            file_entries = [name for name in namelist if not name.endswith('/') and not name.endswith('.env')]
            if not file_entries:
                return zip_bytes
            
            first_parts = file_entries[0].split('/')
            top_dir = ""
            if len(first_parts) > 1:
                potential_top = first_parts[0] + '/'
                if all(name.startswith(potential_top) for name in file_entries):
                    top_dir = potential_top
                    logger.info(f"Removing redundant top level structure directory: '{top_dir}'")
            
            out_file = io.BytesIO()
            with zipfile.ZipFile(out_file, 'w', zipfile.ZIP_DEFLATED) as z_out:
                for name in namelist:
                    if name.endswith('.env') or name.endswith('/.env'):
                        logger.info(f"Pre-existing local variable files excluded: {name}")
                        continue
                    if top_dir:
                        if name.startswith(top_dir) and name != top_dir:
                            new_name = name[len(top_dir):]
                            if new_name:
                                z_out.writestr(new_name, z_in.read(name))
                    else:
                        z_out.writestr(name, z_in.read(name))
            return out_file.getvalue()
    except Exception as e:
        logger.error(f"Error during zip restructuring process: {e}")
        return zip_bytes


def inject_env_into_zip(zip_bytes: bytes, env_content: bytes) -> bytes:
    """Injects custom .env parameters cleanly into memory ZIP representations."""
    try:
        in_file = io.BytesIO(zip_bytes)
        out_file = io.BytesIO()
        with zipfile.ZipFile(in_file, 'r') as z_in, zipfile.ZipFile(out_file, 'w', zipfile.ZIP_DEFLATED) as z_out:
            for item in z_in.infolist():
                if item.filename != ".env":
                    z_out.writestr(item, z_in.read(item.filename))
            z_out.writestr(".env", env_content)
        return out_file.getvalue()
    except Exception as e:
        logger.error(f"Failed to inject .env file into ZIP: {e}")
        return zip_bytes


# --- Loader Code Templates ---

def get_loader_code(encrypted_b64: str, file_id: str, api_url: str) -> str:
    return f'''# Encrypted with secure cryptographic verification wrappers
import base64, sys, time, uuid

try:
    import requests
    from cryptography.fernet import Fernet
except ImportError:
    print("[CRITICAL] Missing loader requirements. Run: pip install requests cryptography")
    sys.exit(1)

ENCRYPTED_CODE = b"{encrypted_b64}"
FILE_ID = "{file_id}"
API_URL = "{api_url}/api/get-key"

def request_authorization(file_id: str) -> str:
    req_id = str(uuid.uuid4())
    print("⏳ Handshaking with secure licensing node...")
    try:
        resp = requests.post(API_URL, json={{"file_id": file_id, "req_id": req_id}}, timeout=15)
        if resp.status_code == 200 or resp.status_code == 202:
            print("🔑 Access pending. Waiting for owner authentication approval (Strict 30s timeout)...")
            start_time = time.time()
            while time.time() - start_time < 30:
                time.sleep(2)
                poll_resp = requests.get(API_URL, params={{"file_id": file_id, "req_id": req_id}}, timeout=10)
                if poll_resp.status_code == 200:
                    data = poll_resp.json()
                    status = data.get("status")
                    if status == "approved":
                        print("✅ Authentication granted. Decrypting environment...")
                        return data.get("key")
                    elif status == "rejected":
                        print("❌ Authentication rejected by developer.")
                        sys.exit(1)
                    elif status == "expired":
                        print("❌ Session timeout: Authorization request expired.")
                        sys.exit(1)
                else:
                    print("❌ Error communicating with secure licenser.")
                    sys.exit(1)
            print("❌ Timeout reached. Session expired.")
            sys.exit(1)
        elif resp.status_code == 404:
            print("❌ Invalid or terminated key license signature.")
            sys.exit(1)
        else:
            print(f"❌ Server connection failure: Code {{resp.status_code}}")
            sys.exit(1)
    except Exception as e:
        print(f"❌ Handshake failed: {{e}}")
        sys.exit(1)

def decrypt_and_run(key_str: str, encrypted_b64: bytes):
    try:
        key = key_str.encode()
        decrypted = Fernet(key).decrypt(base64.b64decode(encrypted_b64)).decode("utf-8")
        exec(compile(decrypted, "<encrypted>", "exec"), {{"__name__": "__main__"}})
    except Exception as e:
        print(f"❌ Failed to decrypt module context: {{e}}")
        sys.exit(1)

if __name__ == "__main__":
    key = request_authorization(FILE_ID)
    decrypt_and_run(key, ENCRYPTED_CODE)
'''


def get_zip_loader_code(encrypted_b64: str, file_id: str, api_url: str) -> str:
    return f'''# Encrypted package with structural routing and authorization system
import base64, sys, os, zipfile, io, time, uuid

try:
    import requests
    from cryptography.fernet import Fernet
except ImportError:
    print("[CRITICAL] Missing loader requirements. Run: pip install requests cryptography")
    sys.exit(1)

ENCRYPTED_ZIP = b"{encrypted_b64}"
FILE_ID = "{file_id}"
API_URL = "{api_url}/api/get-key"

class MemoryZipImporter:
    def __init__(self, zip_data):
        self.zip_file = zipfile.ZipFile(io.BytesIO(zip_data))
        self.files = self.zip_file.namelist()

    def find_spec(self, fullname, path, target=None):
        base_path = fullname.replace('.', '/')
        possible_files = [f"{{base_path}}.py", f"{{base_path}}/__init__.py"]
        for pf in possible_files:
            if pf in self.files:
                from importlib.machinery import ModuleSpec
                return ModuleSpec(fullname, self, is_package=pf.endswith('__init__.py'))
        return None

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        fullname = module.__name__
        base_path = fullname.replace('.', '/')
        possible_files = [f"{{base_path}}.py", f"{{base_path}}/__init__.py"]
        
        code_bytes = None
        filepath = None
        for pf in possible_files:
            if pf in self.files:
                code_bytes = self.zip_file.read(pf)
                filepath = pf
                break
        if code_bytes is None:
            raise ImportError(f"Could not load packaging path: {{fullname}}")
        
        code_obj = compile(code_bytes, filepath, 'exec')
        module.__file__ = filepath
        if filepath.endswith('__init__.py'):
            module.__path__ = [os.path.dirname(filepath)]
        exec(code_obj, module.__dict__)

def request_authorization(file_id: str) -> str:
    req_id = str(uuid.uuid4())
    print("⏳ Handshaking with secure licensing node...")
    try:
        resp = requests.post(API_URL, json={{"file_id": file_id, "req_id": req_id}}, timeout=15)
        if resp.status_code == 200 or resp.status_code == 202:
            print("🔑 Access pending. Waiting for owner authentication approval (Strict 30s timeout)...")
            start_time = time.time()
            while time.time() - start_time < 30:
                time.sleep(2)
                poll_resp = requests.get(API_URL, params={{"file_id": file_id, "req_id": req_id}}, timeout=10)
                if poll_resp.status_code == 200:
                    data = poll_resp.json()
                    status = data.get("status")
                    if status == "approved":
                        print("✅ Authentication granted. Decrypting package...")
                        return data.get("key")
                    elif status == "rejected":
                        print("❌ Authentication rejected by developer.")
                        sys.exit(1)
                    elif status == "expired":
                        print("❌ Session timeout: Authorization request expired.")
                        sys.exit(1)
                else:
                    print("❌ Error communicating with secure licenser.")
                    sys.exit(1)
            print("❌ Timeout reached. Session expired.")
            sys.exit(1)
        elif resp.status_code == 404:
            print("❌ Invalid or terminated key license signature.")
            sys.exit(1)
        else:
            print(f"❌ Server connection failure: Code {{resp.status_code}}")
            sys.exit(1)
    except Exception as e:
        print(f"❌ Handshake failed: {{e}}")
        sys.exit(1)

def decrypt_and_run(key_str: str, encrypted_b64: bytes):
    try:
        key = key_str.encode()
        zip_data = Fernet(key).decrypt(base64.b64decode(encrypted_b64))
        importer = MemoryZipImporter(zip_data)
        sys.meta_path.insert(0, importer)
        
        if ".env" in importer.files:
            try:
                env_content = importer.zip_file.read(".env").decode("utf-8")
                for line in env_content.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        os.environ[k.strip()] = v.strip().strip("'").strip('"')
            except Exception:
                pass
        
        entry_point = "main.py"
        if entry_point not in importer.files:
            if "bot.py" in importer.files:
                entry_point = "bot.py"
            else:
                py_files = [f for f in importer.files if f.endswith('.py')]
                entry_point = py_files[0] if py_files else None
        
        if not entry_point:
            print("❌ Fatal: Entry point execution target not found inside package.")
            sys.exit(1)
            
        main_code = importer.zip_file.read(entry_point)
        code_obj = compile(main_code, entry_point, 'exec')
        sys.path.insert(0, '')
        exec(code_obj, {{"__name__": "__main__", "__file__": entry_point}})
    except Exception as e:
        print(f"❌ Application execution halted: {{e}}")
        sys.exit(1)

if __name__ == "__main__":
    key = request_authorization(FILE_ID)
    decrypt_and_run(key, ENCRYPTED_ZIP)
'''


def get_help_text(admin: bool = False) -> str:
    user_text = (
        "🤖 *CODE PROTECTOR SYSTEM - HELP*\n\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "📤 *HOW TO ENCRYPT?*\n"
        "Simply send me any `.py` or `.zip` file archive.\n"
        "I will apply secure encryption and output a customized executable loader.\n\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "🚀 *INSTRUCTIONS TO HOST:*\n\n"
        "1. Host or launch your downloaded `loader.py` script on Railway, VPS, or local server.\n"
        "2. Make sure required libraries are installed:\n"
        "`pip install requests cryptography`\n"
        "3. Run the executable:\n"
        "`python loader.py`\n\n"
        "4. Whenever it runs, your Telegram account will receive a secure authorization prompt!\n\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "💬 Developer Support: @IM\\_USELESS"
    )
    if not admin:
        return user_text

    admin_text = (
        "\n\n━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "🛡️ *ADMIN CONFIGURATION PORTAL*\n\n"
        "📈 `/status` — Live performance indices (IST)\n"
        "🚫 `/banlist` — Display currently blacklisted records\n"
        "🚫 `/ban <user_id>` — Revoke user access permissions\n"
        "✅ `/unban <user_id>` — Re-enable suspended profiles\n"
        "⚙️ `/limit <user_id> <limit>` — Adjust manual encryption boundaries\n"
        "⚙️ `/setdefault <limit>` — Alter the standard initial boundary limit\n"
        "👤 `/userstatus <user_id>` — Pull full record variables\n"
        "🔄 `/resetuser <user_id>` — Clean daily operational registers\n"
        "🗑️ `/delete <file_id>` — Hard delete structural license traces\n"
        "📢 `/broadcast <text>` — Transmit general broadcast template\n\n"
        "📢 *FORCE SUBSCRIBE CONTROL*\n"
        "• `/add <channel_id> <invite_link> <button_name>`\n"
        "• `/remove <channel_id>` — Discontinue validation criteria\n"
        "• `/list` — Review active subscription paths"
    )
    return user_text + admin_text


# --- Global Error Handler Decorator ---

def handle_errors(func):
    import inspect
    _sig = inspect.signature(func)
    async def wrapper(message: Message, *args, **kwargs):
        valid_kwargs = {k: v for k, v in kwargs.items() if k in _sig.parameters}
        try:
            if message.from_user.id != ADMIN_ID:
                if await check_banned(message.from_user.id):
                    await message.answer("🚫 *Your operational access token has been revoked.* Contact administration @YOUR_USERNAME.")
                    return
            return await func(message, *args, **valid_kwargs)
        except TelegramAPIError as tg_err:
            logger.error(f"Telegram client exception: {tg_err}")
            await message.answer("⚠️ Connection latency or Telegram service exception. Please try again.")
        except Exception as err:
            logger.error(f"Unhandled operational exception: {err}", exc_info=True)
            await message.answer("❌ Service handler exception. Contact @YOUR_USERNAME for support.")
            try:
                await bot.send_message(
                    ADMIN_ID,
                    f"🚨 *CRITICAL ENGINE FAULT*\nUser: `{message.from_user.id}`\nPayload: `{str(err)[:250]}`",
                    parse_mode="Markdown"
                )
            except Exception:
                pass
    return wrapper


# --- Loading Process Animations ---

async def show_loading_animation(message: Message, text: str, steps: List[str]):
    msg = await message.answer("🔄 *Processing context...*", parse_mode="Markdown")
    for i, step in enumerate(steps, 1):
        progress = int((i / len(steps)) * 100)
        bar = "▓" * (progress // 5) + "░" * (20 - progress // 5)
        await msg.edit_text(
            f"⏳ *{text}*\n\n`{bar}` `{progress}%`\n\n📌 *Step {i}/{len(steps)}:* `{step}`",
            parse_mode="Markdown"
        )
        await asyncio.sleep(0.6)
    await msg.delete()


async def show_success_animation(message: Message, text: str):
    msg = await message.answer("✨ *Finalizing...*", parse_mode="Markdown")
    for emoji in ["🔐", "✅", "🎉", "🛡️"]:
        await msg.edit_text(f"{emoji} *{text}*", parse_mode="Markdown")
        await asyncio.sleep(0.2)
    await msg.delete()


# --- User Command Handlers ---

@dp.message(Command("start"))
@handle_errors
async def cmd_start(message: Message):
    user_id = message.from_user.id
    if user_id == ADMIN_ID:
        limit_text = "♾️ System Bypass"
        used_text = "0"
        remaining = "♾️"
        reset_text = "🔓 Administrator clearance enabled"
    else:
        try:
            user = get_or_create_user(user_id)
            user = reset_daily_counter_if_needed(user)
            limit = user.get("daily_limit", 5)
            used = user.get("files_encrypted_today", 0)
            remaining = max(0, limit - used)
            reset_text = f"⏰ Counter resets in: {get_reset_time()}"
            limit_text = str(limit)
            used_text = f"{used}/{limit}"
        except Exception as e:
            logger.error(f"Start registry initialization error: {e}")
            limit_text = "5"
            used_text = "0/5"
            remaining = "5"
            reset_text = "⏰ System cycles daily at 00:00 IST"

    welcome_text = (
        "👋 *Welcome to Code Protector System!*\n\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"📊 *Daily Allowance Limit:* `{limit_text}`\n"
        f"📁 *Processed Items Today:* `{used_text}`\n"
        f"✅ *Quota Allowance Remaining:* `{remaining}`\n"
        f"{reset_text}\n\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "📤 Send me any `.py` or `.zip` file archive to begin encryption.\n"
        "Your runtime loader packages will operate with secure licensing rules.\n\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "💡 Use `/help` to see advanced operations."
    )

    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="📤 Encrypt Files", callback_data="encrypt_help"),
            InlineKeyboardButton(text="❓ Portal Help", callback_data="help_menu")
        ]
    ])
    await message.answer(welcome_text, parse_mode="Markdown", reply_markup=keyboard)


@dp.message(Command("help"))
@handle_errors
async def cmd_help(message: Message):
    await message.answer(get_help_text(admin=(message.from_user.id == ADMIN_ID)), parse_mode="Markdown")


@dp.callback_query(F.data == "help_menu")
async def help_callback(callback: CallbackQuery):
    await callback.message.delete()
    await callback.message.answer(get_help_text(admin=(callback.from_user.id == ADMIN_ID)), parse_mode="Markdown")
    await callback.answer()


@dp.callback_query(F.data == "encrypt_help")
async def encrypt_help_callback(callback: CallbackQuery):
    await callback.message.delete()
    await callback.message.answer(
        "📤 *Direct document upload expected.*\n\n"
        "Upload a `.py` (max 1MB) or zipped `.zip` file structure (max 5MB).\n"
        "I will package it with your dynamic real-time licensing validation module.",
        parse_mode="Markdown"
    )
    await callback.answer()


# --- Admin Command Handlers ---

@dp.message(Command("status"))
@handle_errors
async def cmd_status(message: Message):
    if message.from_user.id != ADMIN_ID:
        return
    try:
        total_users = get_total_users()
        total_encrypted = get_total_encrypted_files()
        total_banned = get_total_banned_count()
        today_activity  = get_today_activity()

        await message.answer(
            "📊 *REAL-TIME METRIC ANALYSIS (IST)*\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"👥 *Total Active Profiles:* `{total_users}`\n"
            f"📁 *Encrypted Modules:* `{total_encrypted}`\n"
            f"🚫 *Blacklisted Registers:* `{total_banned}`\n"
            f"📈 *Processed Today (IST):* `{today_activity}`\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "System Administrative Control: Online",
            parse_mode="Markdown"
        )
    except Exception as e:
        logger.error(f"Metrics collection failed: {e}")
        await message.answer("❌ Error compiling real-time database metric calculations.")


@dp.message(Command("banlist"))
@handle_errors
async def cmd_banlist(message: Message):
    if message.from_user.id != ADMIN_ID:
        return
    try:
        raw_banned = get_banned_users_list()
        banned_users = []
        if isinstance(raw_banned, dict):
            for k, v in raw_banned.items():
                if isinstance(v, dict):
                    banned_users.append({"id": k, "name": v.get("name", "Unknown Profile")})
                else:
                    banned_users.append({"id": k, "name": str(v)})
        elif isinstance(raw_banned, list):
            for item in raw_banned:
                if isinstance(item, dict):
                    banned_users.append(item)
                else:
                    banned_users.append({"id": str(item), "name": "Banned User"})

        if not banned_users:
            return await message.answer("✅ System blacklist register is empty.")

        list_text = "🚫 *CURRENT SYSTEM BLACKLIST*\n\n"
        for i, user in enumerate(banned_users[:30], 1):
            name = user.get('name', 'Unknown')
            uid = user.get('id', 'Unknown')
            list_text += f"{i}. `{uid}` - {name}\n"

        if len(banned_users) > 30:
            list_text += f"\n... and {len(banned_users) - 30} additional records"

        await message.answer(list_text, parse_mode="Markdown")
    except Exception as e:
        logger.error(f"Blacklist indexing failed: {e}")
        await message.answer("❌ Operational error compiling system blacklist.")


@dp.message(Command("limit"))
@handle_errors
async def cmd_limit(message: Message):
    if message.from_user.id != ADMIN_ID:
        return
    parts = message.text.split()
    if len(parts) != 3:
        return await message.answer("❌ Arguments missing: `/limit <user_id> <limit_value>`", parse_mode="Markdown")
    try:
        target_id = int(parts[1])
        new_limit = int(parts[2])
        if new_limit < 1 or new_limit > 10000:
            return await message.answer("❌ Value out of safety limits (1 - 10,000).")
        update_user(target_id, {"daily_limit": new_limit})
        await message.answer(f"✅ Quota updated. User `{target_id}` set to daily limit of `{new_limit}`.", parse_mode="Markdown")
    except Exception as e:
        logger.error(f"User quota adjustment error: {e}")
        await message.answer("❌ Error updating target encryption allowance boundaries.")


@dp.message(Command("setdefault"))
@handle_errors
async def cmd_setdefault(message: Message):
    if message.from_user.id != ADMIN_ID:
        return
    parts = message.text.split()
    if len(parts) != 2 or not parts[1].isdigit():
        return await message.answer("❌ Arguments missing: `/setdefault <limit>`", parse_mode="Markdown")
    limit = int(parts[1])
    if not 1 <= limit <= 10000:
        return await message.answer("❌ Limit must be within safety boundaries (1 - 10,000).")
    try:
        set_default_limit(limit)
        await message.answer(f"✅ Default daily encryption quota updated to `{limit}`.", parse_mode="Markdown")
    except Exception as e:
        logger.error(f"Default limit adjustment failure: {e}")
        await message.answer("❌ Error updating default system settings.")


@dp.message(Command("userstatus"))
@handle_errors
async def cmd_userstatus(message: Message):
    if message.from_user.id != ADMIN_ID:
        return
    parts = message.text.split()
    if len(parts) != 2 or not parts[1].isdigit():
        return await message.answer("❌ Arguments missing: `/userstatus <user_id>`", parse_mode="Markdown")
    target_id = int(parts[1])
    try:
        user = get_user(target_id)
        if not user:
            return await message.answer(f"❌ User ID `{target_id}` is not registered in the database.", parse_mode="Markdown")
        total = count_user_files(target_id)
        remaining = max(0, user.get("daily_limit", 5) - user.get("files_encrypted_today", 0))
        await message.answer(
            f"👤 *USER METRIC ANALYSIS*\n\n"
            f"🆔 Telegram ID: `{user.get('telegram_id', target_id)}`\n"
            f"📊 Daily Allowance: `{user.get('daily_limit', 5)}`\n"
            f"📁 Processed Today: `{user.get('files_encrypted_today', 0)}`\n"
            f"✅ Allowance Remaining: `{remaining}`\n"
            f"📦 Cumulative Encrypted Files: `{total}`\n"
            f"📅 Latest Activity: `{user.get('last_upload_date', 'N/A')}` (IST)",
            parse_mode="Markdown"
        )
    except Exception as e:
        logger.error(f"Telemetry retrieval failed: {e}")
        await message.answer("❌ Database parsing failure.")


@dp.message(Command("resetuser"))
@handle_errors
async def cmd_resetuser(message: Message):
    if message.from_user.id != ADMIN_ID:
        return
    parts = message.text.split()
    if len(parts) != 2 or not parts[1].isdigit():
        return await message.answer("❌ Arguments missing: `/resetuser <user_id>`", parse_mode="Markdown")
    target_id = int(parts[1])
    try:
        user = get_user(target_id)
        if not user:
            return await message.answer(f"❌ User ID `{target_id}` not found.", parse_mode="Markdown")
        old = user.get("files_encrypted_today", 0)
        update_user(target_id, {"files_encrypted_today": 0, "last_upload_date": today_utc()})
        await message.answer(f"✅ User counter reset: `{old}` -> `0`", parse_mode="Markdown")
    except Exception as e:
        logger.error(f"Counter reset failed: {e}")
        await message.answer("❌ Operational registry reset failure.")


@dp.message(Command("delete"))
@handle_errors
async def cmd_delete(message: Message):
    user_id = message.from_user.id
    parts = message.text.split()
    if len(parts) != 2:
        return await message.answer("❌ Syntax missing: `/delete <file_id>`", parse_mode="Markdown")
    file_id = parts[1].strip()
    try:
        file_data = get_file(file_id)
        if not file_data:
            return await message.answer("❌ Specified License ID does not exist in the database.", parse_mode="Markdown")
        owner_id = file_data.get("telegram_id") or file_data.get("user_id")
        if (user_id == ADMIN_ID) or (owner_id and str(owner_id) == str(user_id)):
            delete_file(file_id)
            await message.answer(
                f"🗑️ *LICENSE DEACTIVATED SUCCESSFULLY*\n\n"
                f"License ID `{file_id}` has been deleted. Loader scripts will fail authorization.",
                parse_mode="Markdown"
            )
        else:
            await message.answer("🚫 *Access Violation:* You do not hold ownership privileges for this file.", parse_mode="Markdown")
    except Exception as e:
        logger.error(f"License drop failure: {e}")
        await message.answer("❌ Critical error deleting the target file license.")


@dp.message(Command("ban"))
@handle_errors
async def cmd_ban(message: Message):
    if message.from_user.id != ADMIN_ID:
        return
    parts = message.text.split()
    if len(parts) != 2:
        return await message.answer("❌ Syntax error: `/ban <user_id>`", parse_mode="Markdown")
    try:
        target_id = int(parts[1])
        if target_id == ADMIN_ID:
            return await message.answer("❌ Administrative safety block: Cannot ban developer account!")
        ban_user(target_id)
        user = get_user(target_id)
        name = user.get('username', 'Unknown') if user else 'Unknown'
        safe_name = name.replace("_", "\\_").replace("*", "\\*")
        await message.answer(f"✅ User ID `{target_id}` ({safe_name}) has been blacklisted from system.", parse_mode="Markdown")
        try:
            await bot.send_message(target_id, "🚫 *You have been blacklisted from utilizing this bot service.*")
        except Exception:
            pass
    except Exception as e:
        logger.error(f"Blacklist entry failure: {e}")
        await message.answer("❌ Error writing blacklisted record profile.")


@dp.message(Command("unban"))
@handle_errors
async def cmd_unban(message: Message):
    if message.from_user.id != ADMIN_ID:
        return
    parts = message.text.split()
    if len(parts) != 2:
        return await message.answer("❌ Syntax missing: `/unban <user_id>`", parse_mode="Markdown")
    try:
        target_id = int(parts[1])
        unban_user(target_id)
        await message.answer(f"✅ User ID `{target_id}` restored to active directory.", parse_mode="Markdown")
        try:
            await bot.send_message(target_id, "✅ *Your access permissions have been restored. You may now continue using our encryption services.*")
        except Exception:
            pass
    except Exception as e:
        logger.error(f"Blacklist removal failure: {e}")
        await message.answer("❌ Error removing user from system blacklist.")


@dp.message(Command("broadcast"))
@handle_errors
async def cmd_broadcast(message: Message):
    if message.from_user.id != ADMIN_ID:
        return
    if not message.reply_to_message:
        return await message.answer("❌ *Broadcast execution requires a replied target message.*", parse_mode="Markdown")
    try:
        users = get_all_user_ids()
        if not users:
            return await message.answer("❌ User directory empty.")
        total = len(users)
        status_msg = await message.answer("📤 *Broadcasting context to active directories...*\n⏳ processing pool...", parse_mode="Markdown")
        success = 0
        failed = 0
        for i, user_id in enumerate(users):
            try:
                await message.reply_to_message.copy_to(chat_id=user_id)
                success += 1
            except Exception:
                failed += 1
            await asyncio.sleep(0.04)
            if (i + 1) % 100 == 0:
                await status_msg.edit_text(
                    f"📤 *Broadcasting active...*\n📊 `{i+1}/{total}` profiles processed\n✅ success: {success}\n❌ offline: {failed}",
                    parse_mode="Markdown"
                )
        await status_msg.edit_text(
            f"📢 *BROADCAST TRANSMISSION FINISHED*\n\n✅ Deliveries: `{success}`\n❌ Dead paths: `{failed}`\n👥 Processed pool: `{total}`",
            parse_mode="Markdown"
        )
    except Exception as e:
        logger.error(f"Broadcast processing error: {e}")
        await message.answer(f"❌ Transmission pipeline failure: {e}")


# --- Force Subscribe Command Logic ---

@dp.message(Command("add"))
@handle_errors
async def cmd_add_channel(message: Message):
    if message.from_user.id != ADMIN_ID:
        return
    parts = message.text.split(maxsplit=3)
    if len(parts) < 4:
        return await message.answer(
            "❌ *Invalid Arguments!*\n\n"
            "**Usage:** `/add <channel_id_or_username> <invite_link> <button_name>`\n"
            "**Example:** `/add -100123456789 https://t.me/+InviteLink Join Channel`",
            parse_mode="Markdown"
        )
    chat_id = parts[1].strip()
    invite_link = parts[2].strip()
    button_name = parts[3].strip()

    try:
        target_chat = int(chat_id) if chat_id.startswith("-100") or chat_id.isdigit() else chat_id
        bot_member = await message.bot.get_chat_member(target_chat, message.bot.id)
        if bot_member.status != "administrator":
            return await message.answer(
                "❌ *Verification Failed!*\n\n"
                "The bot is added to the channel but **does not have Administrator permissions**.\n"
                "Please promote the bot to Admin to check member join statuses.",
                parse_mode="Markdown"
            )
    except Exception as e:
        return await message.answer(
            f"❌ *Verification Failed!*\n\n"
            f"The bot is not present in the specified chat, or target ID is invalid.\n\n"
            f"**Error Details:** `{str(e)}`",
            parse_mode="Markdown"
        )

    add_fsub_channel(chat_id, invite_link, button_name)
    await message.answer(
        f"✅ *Force Join configured successfully!*\n\n"
        f"• **Channel Chat ID:** `{chat_id}`\n"
        f"• **Invite Link:** {invite_link}\n"
        f"• **Button Text:** `{button_name}`",
        parse_mode="Markdown",
        disable_web_page_preview=True
    )


@dp.message(Command("remove"))
@handle_errors
async def cmd_remove_channel(message: Message):
    if message.from_user.id != ADMIN_ID:
        return
    parts = message.text.split()
    if len(parts) != 2:
        return await message.answer("❌ *Usage:* `/remove <channel_id_or_username>`", parse_mode="Markdown")
    chat_id = parts[1].strip()
    if remove_fsub_channel(chat_id):
        await message.answer(f"✅ Channel `{chat_id}` has been removed from Force Join requirements.", parse_mode="Markdown")
    else:
        await message.answer(f"❌ Channel `{chat_id}` not found in Force Join configurations.", parse_mode="Markdown")


@dp.message(Command("list"))
@handle_errors
async def cmd_list_channels(message: Message):
    if message.from_user.id != ADMIN_ID:
        return
    channels = get_fsub_channels()
    if not channels:
        return await message.answer("ℹ️ No Force Join channels configured currently.")
    text = "📢 *ACTIVE FORCE JOIN CHANNELS*\n\n"
    for chat_id, data in channels.items():
        text += f"• **ID/Username:** `{chat_id}`\n  **Button Name:** `{data['button_name']}`\n  **Link:** {data['invite_link']}\n\n"
    await message.answer(text, parse_mode="Markdown", disable_web_page_preview=True)


# --- Force Join Verification Callback ---

@dp.callback_query(F.data == "check_join_status")
async def handle_fsub_refresh(callback: CallbackQuery, state: FSMContext):
    user_id = callback.from_user.id
    channels = get_fsub_channels()
    not_joined = []
    for chat_id, ch_data in channels.items():
        try:
            target_chat = int(chat_id) if chat_id.startswith("-100") or chat_id.isdigit() else chat_id
            member = await callback.bot.get_chat_member(target_chat, user_id)
            if member.status not in ["member", "administrator", "creator"]:
                not_joined.append((chat_id, ch_data))
        except Exception:
            continue
    if not_joined:
        await callback.answer("❌ You haven't joined all required channels yet!", show_alert=True)
    else:
        await state.clear()
        await callback.message.delete()
        await callback.message.answer(
            "✅ *Access Granted!*\n\n"
            "Thank you for joining. Your access has been successfully verified! Send me a `.py` or `.zip` file to encrypt.",
            parse_mode="Markdown"
        )
        await callback.answer("Access authorized!")


# --- Admin Decryption Support ---

async def attempt_admin_decryption(message: Message, file_bytes: bytes, file_name: str, user_id: int) -> bool:
    try:
        content_str = file_bytes.decode('utf-8', errors='ignore')
        file_id_match = re.search(r'FILE_ID\s*=\s*["\']([^"\']+)["\']', content_str)
        encrypted_match = re.search(r'ENCRYPTED_(?:CODE|ZIP)\s*=\s*b["\']([^"\']+)["\']', content_str)
        if not (file_id_match and encrypted_match):
            return False
        
        status_msg = await message.answer("🔑 *Admin Decryptor:* Analyzing loader configurations...", parse_mode="Markdown")
        file_id = file_id_match.group(1)
        encrypted_b64 = encrypted_match.group(1)
        is_zip_loader = "ENCRYPTED_ZIP" in content_str
        
        record = get_file(file_id)
        if not record or not record.get("decryption_key"):
            await status_msg.edit_text(
                "❌ *Decryption Failed!*\n\n"
                "**Reason:** `Key Not Found / Record Not Registered`\n\n"
                "💡 *Explanation:* The dynamic database record has expired or was manually deleted.",
                parse_mode="Markdown"
            )
            return True
        
        decryption_key = record["decryption_key"]
        try:
            fernet = Fernet(decryption_key.encode())
            decrypted_data = fernet.decrypt(base64.b64decode(encrypted_b64))
            if is_zip_loader:
                recovered_name = os.path.splitext(file_name)[0].replace("_zip_loader", "") + "_recovered.zip"
            else:
                recovered_name = os.path.splitext(file_name)[0].replace("_loader", "") + "_recovered.py"
            
            await message.answer_document(
                document=BufferedInputFile(decrypted_data, filename=recovered_name),
                caption=(
                    f"✨ *Admin Recovery Successful!*\n\n"
                    f"📄 File Name: `{recovered_name}`\n"
                    f"🔐 File ID: `{file_id}`\n"
                    f"🔑 Decryption Key: `{decryption_key}`"
                ),
                parse_mode="Markdown"
            )
            await status_msg.delete()
            return True
        except Exception as dec_err:
            await status_msg.edit_text(f"❌ *Decryption Failed!*\n\n**Reason:** `Fernet decryption failed ({dec_err})`", parse_mode="Markdown")
            return True
    except Exception as e:
        logger.error(f"Error executing Admin Decryptor: {e}")
        return False


# --- Authorization Request Callback Handlers ---

@dp.callback_query(F.data.startswith("req_accept:"))
async def handle_request_accept(callback: CallbackQuery):
    req_id = callback.data.split(":")[1]
    req_data = fb_get(f"requests/{req_id}")
    
    if not req_data:
        return await callback.answer("❌ Request session missing or expired.", show_alert=True)
        
    if str(req_data.get("owner_id")) != str(callback.from_user.id):
        await callback.answer("🚫 Access Denied: You do not hold ownership privileges for this file.", show_alert=True)
        return

    if req_data.get("status") == "expired":
        await callback.answer("❌ Timeout reached. Session expired.", show_alert=True)
        await callback.message.edit_text(
            "⚠️ *Action Halted:* This authorization window has expired.",
            reply_markup=None,
            parse_mode="Markdown"
        )
        return

    update_request_status(req_id, "approved")
    cleaned_text = callback.message.text
    await callback.message.edit_text(
        f"{cleaned_text}\n\n✅ *Status: Access Authorized!*",
        reply_markup=None,
        parse_mode="Markdown"
    )
    await callback.answer("Access authorized!")


@dp.callback_query(F.data.startswith("req_reject:"))
async def handle_request_reject(callback: CallbackQuery):
    req_id = callback.data.split(":")[1]
    req_data = fb_get(f"requests/{req_id}")
    
    if not req_data:
        return await callback.answer("❌ Request session missing or expired.", show_alert=True)
        
    if str(req_data.get("owner_id")) != str(callback.from_user.id):
        await callback.answer("🚫 Access Denied: You do not hold ownership privileges for this file.", show_alert=True)
        return

    if req_data.get("status") == "expired":
        await callback.answer("❌ Timeout reached. Session expired.", show_alert=True)
        await callback.message.edit_text(
            "⚠️ *Action Halted:* This authorization window has expired.",
            reply_markup=None,
            parse_mode="Markdown"
        )
        return

    update_request_status(req_id, "rejected")
    cleaned_text = callback.message.text
    await callback.message.edit_text(
        f"{cleaned_text}\n\n❌ *Status: Request Rejected*",
        reply_markup=None,
        parse_mode="Markdown"
    )
    await callback.answer("Request denied!")


# --- File Upload Receiver ---

@dp.message(F.document)
@handle_errors
async def handle_document(message: Message, state: FSMContext):
    user_id = message.from_user.id
    doc = message.document
    if not doc.file_name:
        return
    is_py = doc.file_name.lower().endswith(".py")
    is_zip = doc.file_name.lower().endswith(".zip")
    if not is_py and not is_zip:
        return

    max_size = MAX_PY_SIZE if is_py else MAX_ZIP_SIZE
    if doc.file_size > max_size:
        await message.answer(f"❌ *File structure too large.* Maximum allowance: `{int(max_size/1024)} KB`", parse_mode="Markdown")
        return

    if user_id != ADMIN_ID:
        try:
            user = get_or_create_user(user_id)
            user = reset_daily_counter_if_needed(user)
            limit = user.get("daily_limit", 5)
            used = user.get("files_encrypted_today", 0)
            if used >= limit:
                await message.answer("⛔ *Daily limit reached. Quota exhausted today.*")
                return
        except Exception as e:
            logger.error(f"Quota check failed: {e}")
            return

    download_msg = await message.answer("⏳ *Retrieving binary payloads...*", parse_mode="Markdown")
    try:
        file_info = await bot.get_file(doc.file_id)
        file_bytes = await bot.download_file(file_info.file_path)
        file_content = file_bytes.read()
        await download_msg.delete()
        if not file_content:
            return await message.answer("❌ Error: Received empty file payload.")
    except Exception as e:
        await download_msg.delete()
        return await message.answer("❌ Error downloading file payload from cloud storage.")

    # Admin execution pathway
    if user_id == ADMIN_ID:
        await state.set_state(EncryptState.waiting_for_admin_choice)
        await state.update_data(
            file_bytes=base64.b64encode(file_content).decode('utf-8'),
            file_name=doc.file_name,
            user_id=user_id,
            is_py=is_py,
            is_zip=is_zip
        )
        keyboard = InlineKeyboardMarkup(inline_keyboard=[
            [
                InlineKeyboardButton(text="🔐 Encrypt Module", callback_data="admin_encrypt"),
                InlineKeyboardButton(text="🔑 Decrypt Module", callback_data="admin_decrypt")
            ]
        ])
        await message.answer(
            f"📦 *Administrative Control Menu*\n\n📄 Target payload: `{doc.file_name}`\n\nChoose context action:",
            parse_mode="Markdown",
            reply_markup=keyboard
        )
        return

    # Regular client flow
    await state.set_state(EncryptState.waiting_for_project_name)
    await state.update_data(
        file_bytes=base64.b64encode(file_content).decode('utf-8'),
        original_name=doc.file_name,
        is_zip=is_zip,
        is_py=is_py,
        user_id=user_id,
        limit=limit,
        used=used
    )
    await message.answer("📝 *Step 1/2: Project Name*\n\nEnter your project name (max 20 words):", parse_mode="Markdown")


# --- Admin Decision Callbacks ---

@dp.callback_query(F.data == "admin_encrypt")
async def admin_encrypt_callback(callback: CallbackQuery, state: FSMContext):
    data = await state.get_data()
    if not data:
        return await callback.answer("❌ Session expired.")
    await callback.message.delete()
    await state.set_state(EncryptState.waiting_for_project_name)
    await callback.message.answer("📝 *Step 1/2: Project Name*\n\nEnter project name (max 20 words):", parse_mode="Markdown")
    await callback.answer()


@dp.callback_query(F.data == "admin_decrypt")
async def admin_decrypt_callback(callback: CallbackQuery, state: FSMContext):
    data = await state.get_data()
    if not data:
        return await callback.answer("❌ Session expired.")
    await callback.message.delete()
    file_bytes = base64.b64decode(data['file_bytes'])
    file_name = data.get('file_name', 'project.py')
    is_py = data.get('is_py', True)
    await state.clear()
    if not is_py:
        await callback.message.answer("❌ *Decryption Blocked:* ZIP package decrypting is not supported.", parse_mode="Markdown")
        return callback.answer()
    
    is_decrypted = await attempt_admin_decryption(callback.message, file_bytes, file_name, ADMIN_ID)
    if not is_decrypted:
        await callback.message.answer("❌ *Decryption Blocked:* Invalid file format or missing authorization variables.", parse_mode="Markdown")
    await callback.answer()


# --- Interactive Workflow Handlers ---

@dp.message(EncryptState.waiting_for_project_name, F.text)
@handle_errors
async def process_project_name(message: Message, state: FSMContext):
    project_name = message.text.strip()
    if len(project_name.split()) > 20:
        return await message.answer("❌ *Length limit violated:* Maximum 20 words allowed. Re-enter:")
    await state.update_data(project_name=project_name)
    await state.set_state(EncryptState.waiting_for_output_name)
    await message.answer("📄 *Step 2/2: Custom Output Name*\n\nEnter your desired file output name (without `.py` suffix, max 15 words):", parse_mode="Markdown")


@dp.message(EncryptState.waiting_for_output_name, F.text)
@handle_errors
async def process_output_name(message: Message, state: FSMContext):
    output_name = message.text.strip()
    if len(output_name.split()) > 15:
        return await message.answer("❌ *Length limit violated:* Maximum 15 words allowed. Re-enter:")
    if output_name.lower().endswith(".py"):
        output_name = output_name[:-3].strip()
    data = await state.get_data()
    is_zip = data.get("is_zip")
    await state.update_data(output_name=output_name)

    if is_zip:
        await state.set_state(EncryptState.waiting_for_env)
        keyboard = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="⏭️ Skip / Continue without .env", callback_data="skip_env")]
        ])
        await message.answer(
            "📂 *Zipped Package Optional: .env Setup*\n\n"
            "Would you like to bind environment configuration files inside this runtime execution?\n\n"
            "👉 *To Setup:* Upload your target `.env` structure or send it as raw parameters text.\n"
            "👉 *To Decline:* Tap **[Skip]** below.",
            parse_mode="Markdown",
            reply_markup=keyboard
        )
    else:
        file_bytes = base64.b64decode(data['file_bytes'])
        await state.clear()
        await finalize_encryption_and_send(
            message, 
            file_bytes=file_bytes, 
            file_name=f"{output_name}.py", 
            project_name=data['project_name'], 
            user_id=data['user_id'], 
            limit=data['limit'], 
            used=data['used'],
            is_zip=False
        )


# --- ZIP Environment Handling ---

@dp.callback_query(F.data == "skip_env")
async def handle_skip_env(callback: CallbackQuery, state: FSMContext):
    data = await state.get_data()
    if not data:
        return await callback.answer("Session expired.")
    await callback.message.delete()
    zip_bytes = base64.b64decode(data['file_bytes'])
    cleaned_zip = restructure_and_strip_env(zip_bytes)
    await state.clear()
    await finalize_encryption_and_send(
        callback.message, 
        file_bytes=cleaned_zip, 
        file_name=f"{data['output_name']}.py", 
        project_name=data['project_name'], 
        user_id=data['user_id'], 
        limit=data['limit'], 
        used=data['used'],
        is_zip=True
    )
    await callback.answer()


@dp.message(EncryptState.waiting_for_env, F.document)
@handle_errors
async def handle_env_file(message: Message, state: FSMContext):
    doc = message.document
    if doc.file_name != ".env":
        return await message.answer("❌ Error: Target file must be exactly named `.env`.")
    data = await state.get_data()
    if not data:
        return await message.answer("Session expired.")
    proc_msg = await message.answer("⏳ Integrating environment configuration variables...")
    try:
        file_info = await bot.get_file(doc.file_id)
        env_stream = await bot.download_file(file_info.file_path)
        env_bytes = env_stream.read()
        zip_bytes = base64.b64decode(data['file_bytes'])
        cleaned_zip = restructure_and_strip_env(zip_bytes)
        injected_zip = inject_env_into_zip(cleaned_zip, env_bytes)
        await state.clear()
        await proc_msg.delete()
        await finalize_encryption_and_send(
            message, 
            file_bytes=injected_zip, 
            file_name=f"{data['output_name']}.py", 
            project_name=data['project_name'], 
            user_id=data['user_id'], 
            limit=data['limit'], 
            used=data['used'],
            is_zip=True
        )
    except Exception as e:
        logger.error(f"Failed to integrate .env document: {e}")
        await proc_msg.delete()
        await message.answer("❌ Error: Failed parsing environment document targets.")


@dp.message(EncryptState.waiting_for_env, F.text)
@handle_errors
async def handle_env_text(message: Message, state: FSMContext):
    env_bytes = message.text.encode('utf-8')
    data = await state.get_data()
    if not data:
        return await message.answer("Session expired.")
    proc_msg = await message.answer("⏳ Processing environment variables text...")
    try:
        zip_bytes = base64.b64decode(data['file_bytes'])
        cleaned_zip = restructure_and_strip_env(zip_bytes)
        injected_zip = inject_env_into_zip(cleaned_zip, env_bytes)
        await state.clear()
        await proc_msg.delete()
        await finalize_encryption_and_send(
            message, 
            file_bytes=injected_zip, 
            file_name=f"{data['output_name']}.py", 
            project_name=data['project_name'], 
            user_id=data['user_id'], 
            limit=data['limit'], 
            used=data['used'],
            is_zip=True
        )
    except Exception as e:
        logger.error(f"Failed to parse target environment text: {e}")
        await proc_msg.delete()
        await message.answer("❌ Operational error handling environment text variables.")


# --- Final Encryption Process ---

async def finalize_encryption_and_send(
    message: Message, 
    file_bytes: bytes, 
    file_name: str, 
    project_name: str, 
    user_id: int, 
    limit: float, 
    used: int,
    is_zip: bool
):
    await show_loading_animation(
        message,
        "Encrypting targets with custom licensing keys...",
        [
            "Compiling Fernet structural variables",
            "Encrypting program binary payload blocks",
            "Registering license metadata signatures",
            "Structuring dynamic runtime verification loader"
        ]
    )
    try:
        fernet_key = Fernet.generate_key()
        encrypted = Fernet(fernet_key).encrypt(file_bytes)
        encrypted_b64 = base64.b64encode(encrypted).decode("utf-8")
        file_id = uuid.uuid4().hex
        
        save_file(file_id, user_id, fernet_key.decode("utf-8"))
        save_project_metadata(file_id, project_name, file_name)

        if user_id != ADMIN_ID:
            used = increment_user_counter(user_id)
            remaining = max(0, limit - used)
        else:
            remaining = "♾️"

        if is_zip:
            loader_code = get_zip_loader_code(encrypted_b64, file_id, API_SERVER_URL)
        else:
            loader_code = get_loader_code(encrypted_b64, file_id, API_SERVER_URL)

        await show_success_animation(message, "Module Encrypted Successfully!")
        limit_text = "♾️ Unlimited Admin Quota" if user_id == ADMIN_ID else str(limit)
        remaining_text = str(remaining)
        reset_text = "🔓 Administrator mode active" if user_id == ADMIN_ID else f"⏰ Limit resets in: {get_reset_time()}"

        safe_filename = file_name.replace("_", "\\_").replace("*", "\\*")
        safe_projectname = project_name.replace("_", "\\_").replace("*", "\\*")

        response_text = (
            "✅ *Code Encrypted & Protected!*\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"📄 *Output Module:* `{safe_filename}`\n"
            f"🏷️ *Linked Project:* `{safe_projectname}`\n"
            f"🔐 *License Reference ID:* `{file_id}`\n\n"
            f"📊 *Today Quota Used:* `{used}/{limit_text}`\n"
            f"✅ *Quota Allowance Remaining:* `{remaining_text}`\n"
            f"{reset_text}\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "📥 *Dynamic Executable Loader Attached below.*\n\n"
            "⚠️ *SECURITY REGISTRY WARNING:* When any host tries to execute this script, "
            "your Telegram account will receive a secure Approve/Reject prompt. "
            "The authorization window has a strict safety limit of **30 seconds**."
        )
        await message.answer_document(
            document=BufferedInputFile(loader_code.encode(), filename=file_name),
            caption=response_text,
            parse_mode="Markdown",
            link_preview_options=LinkPreviewOptions(is_disabled=True)
        )
        logger.info(f"User {user_id} successfully encrypted project '{project_name}' [ID: {file_id}]")
    except Exception as e:
        logger.error(f"Encryption sequence failed: {e}", exc_info=True)
        await message.answer("❌ System Exception: Encryption task halted unexpectedly.")


@dp.message()
async def handle_other_messages(message: Message):
    await message.answer(
        "🤔 I can only accept `.py` or `.zip` archives directly to initiate our encryption flow.\n"
        "Use `/help` to see administrative commands.",
        parse_mode="Markdown"
    )


# --- Background Tasks ---

async def log_cleanup_task():
    """Silent background task to clear console logs and screen every 10 minutes (600 seconds) secretly."""
    while True:
        await asyncio.sleep(600)
        try:
            if os.name == 'nt':
                os.system('cls')
            else:
                os.system('clear')
            logger.info("System background check: console logs cleared secretly (10 min cycle).")
        except Exception as e:
            logger.error(f"Silent console log cleanup failed: {e}")


async def auto_cleanup_task():
    """Cycles every 12 hours checking for licenses older than 7 days, purging them dynamically."""
    while True:
        try:
            logger.info("Executing 7-day database license audit...")
            files_data = fb_get("files")
            if isinstance(files_data, dict):
                now = datetime.now(IST)
                deleted_count = 0
                for file_id, data in files_data.items():
                    if isinstance(data, dict) and data.get("created_at"):
                        try:
                            created_at = datetime.fromisoformat(data["created_at"])
                            if created_at.tzinfo is None:
                                created_at = created_at.replace(tzinfo=IST)
                            age_days = (now - created_at).days
                            if age_days >= 7:
                                delete_file(file_id)
                                deleted_count += 1
                        except Exception as parse_err:
                            logger.error(f"Error checking timestamps during cleanup: {parse_err}")
                if deleted_count > 0:
                    logger.info(f"Cleanup finished! Removed {deleted_count} stale database records.")
        except Exception as e:
            logger.error(f"Error executing auto cleanup: {e}")
        await asyncio.sleep(43200)


async def request_timeout_monitor_task():
    """Monitors pending key authorization timeouts strictly at 30 seconds."""
    while True:
        try:
            requests_data = fb_get("requests")
            if isinstance(requests_data, dict):
                now = datetime.now(timezone.utc)
                for req_id, data in requests_data.items():
                    if isinstance(data, dict) and data.get("status") == "pending":
                        created_at_str = data.get("created_at")
                        if created_at_str:
                            try:
                                created_at = datetime.fromisoformat(created_at_str)
                                elapsed_seconds = (now - created_at).total_seconds()
                                if elapsed_seconds >= 30:
                                    fb_update(f"requests/{req_id}", {
                                        "status": "expired",
                                        "expired_at": now.isoformat()
                                    })
                                    owner_id = data.get("owner_id")
                                    message_id = data.get("message_id")
                                    project_name = data.get("project_name", "Unknown Project")
                                    if owner_id and message_id:
                                        try:
                                            await bot.edit_message_text(
                                                chat_id=owner_id,
                                                message_id=message_id,
                                                text=(
                                                    f"⚠️ *Key Request Expired!*\n\n"
                                                    f"• **Project Name:** `{project_name}`\n"
                                                    f"• **Reason:** `The 30-second authorization window has closed.`"
                                                ),
                                                reply_markup=None,
                                                parse_mode="Markdown"
                                            )
                                            logger.info(f"Request timeout closed: {req_id}")
                                        except TelegramAPIError as tg_err:
                                            logger.warning(f"Failed to modify timeout alert message: {tg_err}")
                            except Exception as parse_err:
                                logger.error(f"Error checking timeout timestamp: {parse_err}")
        except Exception as e:
            logger.error(f"Timeout monitor task exception: {e}")
        await asyncio.sleep(2)


# --- Program Main Startup ---

async def main():
    logger.info("Starting Code Protector Engine...")
    try:
        init_firebase()
        logger.info("Database instance linked successfully.")
    except Exception as e:
        logger.critical(f"Database linkage failed: {e}")
        sys.exit(1)

    # 🚀 RENDER FIX: Launch Flask HTTP Server for Health Checks
    keep_alive()

    dp.update.outer_middleware(ForceJoinMiddleware())
    logger.info("Middleware registered successfully.")

    # Starting long-running loops in asynchronous tasks
    asyncio.create_task(log_cleanup_task())  # Secret 10-Minute Log Clear
    asyncio.create_task(auto_cleanup_task())  # 12-Hour License Clean Cycle
    asyncio.create_task(request_timeout_monitor_task())  # 30s Interactive Timeout Sweep
    logger.info("Background telemetry monitoring tasks are active.")

    try:
        await dp.start_polling(bot, skip_updates=True)
    except Exception as e:
        logger.critical(f"Polling crash detected: {e}", exc_info=True)
        raise

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        logger.info("Engine turned off.")