import json
import os
import sys
import random
import string
import hashlib
import tempfile
import threading
from pathlib import Path

from loguru import logger
from telegram import Update, ReplyKeyboardMarkup, KeyboardButton
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
    CallbackContext,
)


TELEGRAM_API_TOKEN = os.getenv("TELEGRAM_API_TOKEN")
FPTN_WELCOME_MESSAGE = os.getenv("FPTN_WELCOME_MESSAGE")
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

start_keyboard = ReplyKeyboardMarkup(
    [
        [
            KeyboardButton("Get access file"),
        ]
    ],
    resize_keyboard=True,
)


async def start(update: Update, context: CallbackContext) -> None:
    await update.message.reply_text(
        FPTN_WELCOME_MESSAGE,
        reply_markup=start_keyboard,
    )
    logger.info(f"User {update.message.from_user.id} started the bot.")


async def send_credentials_file(
    update: Update, context: CallbackContext, username: str, password: str
) -> None:
    # Create a unique temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".fptn") as temp_file:
        data = {
            "version": 1,
            "service_name": SERVICE_NAME,
            "username": username,
            "password": password,
            "servers": SERVERS_LIST,
        }
        temp_file_path = temp_file.name
        temp_file.write(json.dumps(data, indent=4).encode("utf-8"))
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


async def get_access_file(update: Update, context: CallbackContext) -> None:
    user_id = update.message.from_user.id
    if user_manager.is_registered(user_id):
        username, password = user_manager.reset_password(user_id)
    else:
        username, password = user_manager.register_user(user_id)
    if password:
        await update.message.reply_text(
            f"You have been successfully registered!\n\n"
            f"Please use the provided file to connect to our service.\n\n"
        )
        await send_credentials_file(update, context, username, password)
    else:
        await update.message.reply_text("You are already registered!")


async def update_keyboard(update: Update, context: CallbackContext) -> None:
    new_keyboard = ReplyKeyboardMarkup(
        start_keyboard,
        resize_keyboard=True,
    )
    await update.message.reply_text(
        "Updated!",
        reply_markup=new_keyboard,
    )


def main() -> None:
    if not TELEGRAM_API_TOKEN:
        logger.error(
            "API_TOKEN is not set. Please set the TELEGRAM_API_TOKEN environment variable."
        )
        sys.exit(1)
    application = Application.builder().token(TELEGRAM_API_TOKEN).build()

    application.add_handler(CommandHandler("start", start))
    application.add_handler(
        MessageHandler(filters.TEXT & filters.Regex("Get access file"), get_access_file)
    )
    application.add_handler(
        MessageHandler(filters.TEXT & filters.Regex("Update keyboard"), update_keyboard)
    )
    logger.info("Bot started and is polling for messages.")
    application.run_polling()


if __name__ == "__main__":
    init_logger()
    main()
