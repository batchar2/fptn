import json
import os
import sys
import base64
import random
import string
import hashlib
import threading
from pathlib import Path

from loguru import logger
from telegram import Update, ReplyKeyboardMarkup, KeyboardButton
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

with open(SERVERS_LIST_FILE, "r") as fp:
    SERVERS_LIST = json.load(fp)


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
                        username, hashed_password, _ = parts
                        users[username] = hashed_password
        return users

    def save_users(self, users: dict):
        self.users_file.parent.mkdir(
            parents=True, exist_ok=True
        )  # Ensure the directory exists
        with self.users_file.open("w") as file:
            for username, hashed_password in users.items():
                file.write(
                    f"{username} {hashed_password} {MAX_USER_SPEED_LIMIT}\n"
                )  # Default balance

    def register_user(self, user_id: int) -> (str, str):
        username = f"user{user_id}"
        with self.user_data_lock:
            users = self.load_users()
            if username in users:
                logger.info(
                    f"User {user_id} attempted to register but is already registered."
                )
                return username, None
            else:
                password = self._generate_password()
                hashed_password = self._hash_password(password)
                users[username] = hashed_password
                self.save_users(users)
                logger.info(f"User {user_id} registered with username: {username}")
                return username, password

    def is_registered(self, user_id: int) -> bool:
        username = f"user{user_id}"
        with self.user_data_lock:
            users = self.load_users()
            if username in users:
                return True
        return False

    def reset_password(self, user_id: int) -> (str, str):
        username = f"user{user_id}"
        with self.user_data_lock:
            users = self.load_users()
            if username in users:
                new_password = self._generate_password()
                hashed_password = self._hash_password(new_password)
                users[username] = hashed_password
                self.save_users(users)
                logger.info(f"User {user_id} reset password.")
                return username, new_password
            else:
                logger.info(
                    f"User {user_id} attempted to reset password but is not registered."
                )
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
    language_code = update.message.from_user.language_code or "en"
    messages = MESSAGES.get(language_code, MESSAGES["en"])
    new_keyboard = [
        [KeyboardButton(messages["token_button"])],
    ]
    reply_markup = ReplyKeyboardMarkup(new_keyboard, resize_keyboard=True)
    await update.message.reply_text(
        messages["welcome"],
        reply_markup=reply_markup,
        parse_mode=ParseMode.MARKDOWN,
        disable_web_page_preview=True,
    )
    logger.info(f"User {update.message.from_user.id} started the bot.")


def generate_access_link(username: str, password: str) -> str:
    data = {
        "version": 1,
        "service_name": SERVICE_NAME,
        "username": username,
        "password": password,
        "servers": SERVERS_LIST,
    }
    serialized_content = json.dumps(data)
    base64_content = (
        base64.b64encode(serialized_content.encode("utf-8")).decode().replace("=", "")
    )
    # return f"fptn://{base64_content}"
    return f"fptn:{base64_content}"


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

    fptn_link = generate_access_link(username, password)
    click_to_copy = messages["click_to_copy"]
    info = messages["info"]
    await update.message.reply_text(
        f"{status_message}\n\n"
        f"{info}\n\n\n"
        f"{click_to_copy}\n\n" 
        f"`{fptn_link}`",
        parse_mode=ParseMode.MARKDOWN,
        disable_web_page_preview=True,
    )


def main() -> None:
    if not TELEGRAM_API_TOKEN:
        logger.error(
            "API_TOKEN is not set. Please set the TELEGRAM_API_TOKEN environment variable."
        )
        sys.exit(1)

    application = Application.builder().token(TELEGRAM_API_TOKEN).build()

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("token", get_access_token))

    application.add_handler(
        MessageHandler(
            filters.TEXT & filters.Regex("Get access token"), get_access_token
        )
    )
    application.add_handler(
        MessageHandler(
            filters.TEXT & filters.Regex("Получить токен доступа"),
            get_access_token,
        )
    )
    logger.info("Bot started and is polling for messages.")
    application.run_polling()


if __name__ == "__main__":
    init_logger()
    main()
