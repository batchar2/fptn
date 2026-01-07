import json
import os
import sys
import base64
import random
import string
import hashlib
import tempfile
import threading
from pathlib import Path

import brotli

from loguru import logger
from telegram import Update, ReplyKeyboardMarkup, KeyboardButton, ReplyKeyboardRemove
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
    CallbackContext,
)


TELEGRAM_API_TOKEN = os.getenv("TELEGRAM_API_TOKEN")
FPTN_WELCOME_MESSAGE_EN = os.getenv("FPTN_WELCOME_MESSAGE_EN", "")
FPTN_WELCOME_MESSAGE_RU = os.getenv("FPTN_WELCOME_MESSAGE_RU", "")

MAX_USER_SPEED_LIMIT = int(os.getenv("MAX_USER_SPEED_LIMIT"))
SERVICE_NAME = os.getenv("SERVICE_NAME")
USERS_FILE = Path(os.getenv("USERS_FILE", "/etc/fptn/users.list"))
SERVERS_LIST_FILE = os.getenv("SERVERS_LIST_FILE")
SERVERS_CENSORED_LIST_FILE = os.getenv("SERVERS_CENSORED_LIST_FILE")

ENABLE_BROTLI_COMPRESSION = os.getenv("ENABLE_BROTLI_COMPRESSION", "false").lower() == "true"


with open(SERVERS_LIST_FILE, "r") as fp:
    SERVERS_LIST = json.load(fp)

if SERVERS_CENSORED_LIST_FILE is not None:
    with open(SERVERS_CENSORED_LIST_FILE, "r") as fp:
        SERVERS_CENSORED_LIST = json.load(fp)
else:
    SERVERS_CENSORED_LIST = []


def init_logger():
    logger.remove()  # Remove default logger
    log_file = Path(os.getenv("LOG_FILE", "/var/log/fptn_bot.log"))
    log_file.parent.mkdir(parents=True, exist_ok=True)
    logger.add(
        str(log_file),
        level="INFO",
        format="{time} - {level} - {message}",
        rotation="1 MB",
    )
    logger.add(sys.stdout, level="INFO", format="{time} - {level} - {message}")


class UserManager:
    def __init__(self, users_file: Path):
        self.users_file = users_file
        self.user_data_lock = threading.Lock()

    def _generate_password(self, length=8) -> str:
        return "".join(random.choice(string.ascii_letters) for _ in range(length))

    def _hash_password(self, password: str) -> str:
        sha256 = hashlib.sha256()
        sha256.update(password.encode("utf-8"))
        return sha256.hexdigest()

    def load_users(self) -> dict:
        users = {}
        if self.users_file.exists():
            with self.users_file.open("r") as file:
                for line in file:
                    parts = line.strip().split()
                    if len(parts) == 3:
                        username, hashed_password, speed = parts
                        users[username] = {"password": hashed_password, "speed": speed}
        return users

    def save_users(self, users: dict):
        self.users_file.parent.mkdir(parents=True, exist_ok=True)
        with self.users_file.open("w") as file:
            for username, data in users.items():
                file.write(f"{username} {data['password']} {data['speed']}\n")

    def register_user(self, user_id: str) -> (str, str):
        username = f"user{user_id}"
        with self.user_data_lock:
            users = self.load_users()
            if username in users:
                logger.info(f"User {user_id} attempted to register but is already registered.")
                return username, None
            else:
                password = self._generate_password()
                hashed_password = self._hash_password(password)
                users[username] = {"password": hashed_password, "speed": str(MAX_USER_SPEED_LIMIT)}
                self.save_users(users)
                logger.info(f"User {user_id} registered with username: {username}")
                return username, password

    def is_registered(self, user_id: str) -> bool:
        username = f"user{user_id}"
        with self.user_data_lock:
            users = self.load_users()
            return username in users

    def reset_password(self, user_id: str) -> (str, str):
        username = f"user{user_id}"
        with self.user_data_lock:
            users = self.load_users()
            if username in users:
                new_password = self._generate_password()
                hashed_password = self._hash_password(new_password)
                current_speed = users[username]["speed"]
                users[username] = {"password": hashed_password, "speed": current_speed}
                self.save_users(users)
                logger.info(f"User {user_id} reset password.")
                return username, new_password
            else:
                logger.info(f"User {user_id} attempted to reset password but is not registered.")
                return username, None


user_manager = UserManager(USERS_FILE)


async def start(update: Update, context: CallbackContext) -> None:
    MESSAGES = {
        "en": {
            "welcome": FPTN_WELCOME_MESSAGE_EN,
            "token_button": "Get access token",
        },
        "ru": {
            "welcome": FPTN_WELCOME_MESSAGE_RU,
            "token_button": "Получить токен доступа",
        },
    }
    try:
        language_code = update.message.from_user.language_code or "en"
        messages = MESSAGES.get(language_code, MESSAGES["en"])
        await update.message.reply_text(
            messages["welcome"],
            parse_mode=ParseMode.MARKDOWN,
            disable_web_page_preview=True,
            reply_markup=ReplyKeyboardRemove(),
        )
        logger.info(f"User {update.message.from_user.id} started the bot.")
    except Exception as e:
        logger.error(f"Error: {e}")


def generate_token(username: str, password: str) -> str:
    data = {
        "version": 1,
        "service_name": SERVICE_NAME,
        "username": username,
        "password": password,
        "servers": SERVERS_LIST,
        "censored_zone_servers": SERVERS_CENSORED_LIST,
    }
    return json.dumps(data, separators=(",", ":"))


def generate_access_link(token: str) -> str:
    if ENABLE_BROTLI_COMPRESSION is True:
        compressed = brotli.compress(token.encode("utf-8"), quality=11, lgwin=24, lgblock=24, mode=brotli.MODE_TEXT)
        return "fptnb:" + base64.b64encode(compressed).decode("utf-8").replace("=", "")
    return "fptn:" + base64.b64encode(token.encode("utf-8")).decode().replace("=", "")


async def get_access_token(update: Update, context: CallbackContext) -> None:
    MESSAGES = {
        "en": {
            "status_registered": "🎉✨ You have successfully registered! 🎉",
            "status_reset": "🔑 Your  token has been reset! 🔑",
            "info": "🌐 _ You can download the client from the official project website _ [https://batchar2.github.io/fptn/](https://batchar2.github.io/fptn/)",
            "click_to_copy": "📋💾 Tap the **token below** to copy it and paste it into the app! ⬇️",
        },
        "ru": {
            "status_registered": "🎉✨ Вы успешно зарегистрированы! 🎉",
            "status_reset": "🔑 Ваш токен был сброшен!🔑",
            "info": "🌐 _ Клиент можно скачать с официального сайта проекта _ [https://batchar2.github.io/fptn/](https://batchar2.github.io/fptn/) ",
            "click_to_copy": "📋💾 Нажмите на **токен ниже**, чтобы скопировать и вставите его в приложение! ⬇️",
        },
    }
    user_id = update.message.from_user.id
    language_code = update.message.from_user.language_code or "en"
    messages = MESSAGES.get(language_code, MESSAGES["en"])

    if user_manager.is_registered(user_id):
        username, password = user_manager.reset_password(user_id)
        status_message = messages["status_reset"]
    else:
        username, password = user_manager.register_user(user_id)
        status_message = messages["status_registered"]

    token = generate_token(username, password)
    fptn_link = generate_access_link(token)
    click_to_copy = messages["click_to_copy"]
    info = messages["info"]
    await update.message.reply_text(
        f"{status_message}\n\n" f"{info}\n\n\n" f"{click_to_copy}\n\n" f"`{fptn_link}`",
        parse_mode=ParseMode.MARKDOWN,
        disable_web_page_preview=True,
    )


async def send_credentials_file(update: Update, context: CallbackContext, token: str) -> None:
    # Create a unique temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".fptn") as temp_file:
        temp_file_path = temp_file.name
        temp_file.write(token.encode("utf-8"))
    try:
        await context.bot.send_document(
            chat_id=update.message.chat_id,
            document=open(temp_file_path, "rb"),
            filename=f"{SERVICE_NAME}.fptn",
        )
        logger.info(f"Sent credentials file to user {update.message.from_user.id}.")
    except Exception as e:
        logger.error(f"Failed to send credentials file: {e}")
    finally:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)


def main() -> None:
    if not TELEGRAM_API_TOKEN:
        logger.error("API_TOKEN is not set. Please set the TELEGRAM_API_TOKEN environment variable.")
        sys.exit(1)

    application = Application.builder().token(TELEGRAM_API_TOKEN).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("token", get_access_token))
    # depricated old function
    application.add_handler(CommandHandler("token_mac", get_access_token))

    # UPDATE KEYBOARD (OLD VERSION)
    application.add_handler(MessageHandler(filters.TEXT & filters.Regex("Get access file"), start))
    logger.info("Bot started and is polling for messages.")
    application.run_polling()


if __name__ == "__main__":
    init_logger()
    main()
