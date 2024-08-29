import os
import sys
import random
import string
import hashlib
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
FPTN_SERVER_HOST = os.getenv("FPTN_SERVER_HOST")
FPTN_SERVER_PORT = os.getenv("FPTN_SERVER_PORT")
USERS_FILE = Path(os.getenv("USERS_FILE", "/etc/fptn/users.list"))


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
                file.write(f"{username} {hashed_password} {MAX_USER_SPEED_LIMIT}\n")  # Default balance

    def register_user(self, user_id: int) -> (str, str):
        username = f"user_{user_id}"
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

    def reset_password(self, user_id: int) -> (str, str):
        username = f"user_{user_id}"
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
    [[KeyboardButton("Register"), KeyboardButton("Reset Password")]],
    resize_keyboard=True,
)


async def start(update: Update, context: CallbackContext) -> None:
    await update.message.reply_text(
        FPTN_WELCOME_MESSAGE,
        reply_markup=start_keyboard,
    )
    logger.info(f"User {update.message.from_user.id} started the bot.")


async def register_user(update: Update, context: CallbackContext) -> None:
    user_id = update.message.from_user.id
    username, password = user_manager.register_user(user_id)
    if password:
        await update.message.reply_text(
            f"You have been successfully registered!\n\n"
            f"Server: {FPTN_SERVER_HOST}\n"
            f"Port: {FPTN_SERVER_PORT}\n"
            f"Login: {username}\n"
            f"Password: {password}\n"
        )
    else:
        await update.message.reply_text("You are already registered!")


async def reset_password(update: Update, context: CallbackContext) -> None:
    user_id = update.message.from_user.id
    username, new_password = user_manager.reset_password(user_id)

    if new_password:
        await update.message.reply_text(
            f"Your password was reset!\n\n"
            f"Server: {FPTN_SERVER_HOST}\n"
            f"Port: {FPTN_SERVER_PORT}\n"
            f"Login: {username}\n"
            f"Password: {new_password}\n"
        )
    else:
        await update.message.reply_text(
            "You are not registered. Please register first."
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
        MessageHandler(filters.TEXT & filters.Regex("Register"), register_user)
    )
    application.add_handler(
        MessageHandler(filters.TEXT & filters.Regex("Reset Password"), reset_password)
    )

    logger.info("Bot started and is polling for messages.")
    application.run_polling()


if __name__ == "__main__":
    init_logger()
    main()
