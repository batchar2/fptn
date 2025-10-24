#!/bin/bash

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# --- Welcome Message ---
echo "----------------------------------------------------"
echo "Добро пожаловать в скрипт автоматической установки!"
echo "Этот скрипт поможет вам настроить и запустить"
echo "Telegram-бота и Grafana для мониторинга."
echo "----------------------------------------------------"
echo ""

# --- Check for Docker and Docker Compose ---
echo "Проверка наличия Docker и Docker Compose..."
if ! command_exists docker || ! command_exists docker-compose; then
    echo "Ошибка: Docker или Docker Compose не установлены."
    echo "Пожалуйста, установите их, прежде чем продолжить."
    echo "Инструкция по установке Docker: https://docs.docker.com/engine/install/ubuntu/"
    exit 1
fi
echo "Docker и Docker Compose найдены."
echo ""

# --- Gather User Input ---
echo "Пожалуйста, введите необходимые данные:"

read -p "1. Введите API-токен вашего Telegram-бота: " TELEGRAM_API_TOKEN
read -p "2. Введите хост или IP-адрес вашего FPTN-сервера (для бота): " FPTN_SERVER_HOST
read -p "3. Введите порт вашего FPTN-сервера (для бота): " FPTN_SERVER_PORT
read -p "4. Введите ваш публичный IP-адрес (для Grafana): " FPTN_HOST_GRAFANA
read -p "5. Введите порт вашего FPTN-сервера (для Grafana): " FPTN_PORT_GRAFANA

echo ""
echo "----------------------------------------------------"
echo "Настройка Telegram-бота..."
echo "----------------------------------------------------"

# --- Configure Telegram Bot ---
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd "$SCRIPT_DIR/telegram-bot" || { echo "Ошибка: не удалось найти директорию sysadmin-tools/telegram-bot"; exit 1; }

# Create .env file
echo "Создание конфигурационного файла .env..."
cp .env.demo .env

# Replace values in .env file
sed -i "s/API_TOKEN=.*/API_TOKEN=$TELEGRAM_API_TOKEN/" .env
sed -i "s/FPTN_SERVER_HOST=.*/FPTN_SERVER_HOST=$FPTN_SERVER_HOST/" .env
sed -i "s/FPTN_SERVER_PORT=.*/FPTN_SERVER_PORT=$FPTN_SERVER_PORT/" .env

echo ".env файл успешно настроен."

# Copy server config files
echo "Копирование файлов конфигурации серверов..."
cp servers.json.demo servers.json
cp servers_censored_zone.json.demo servers_censored_zone.json

echo "Важно: не забудьте отредактировать файлы 'servers.json' и 'servers_censored_zone.json', добавив информацию о ваших серверах."
echo ""

# Build and run the bot
echo "Сборка и запуск Docker-контейнера для бота..."
docker-compose build
docker-compose up -d

echo "Telegram-бот успешно запущен!"
echo ""

# --- Configure Grafana ---
echo "----------------------------------------------------"
echo "Настройка Grafana..."
echo "----------------------------------------------------"

cd "$SCRIPT_DIR/grafana" || { echo "Ошибка: не удалось найти директорию sysadmin-tools/grafana"; exit 1; }

# Generate a random secret key for Prometheus
PROMETHEUS_SECRET_ACCESS_KEY=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32 ; echo '')

# Create .env file
echo "Создание конфигурационного файла .env для Grafana..."
cp .env.demo .env

# Replace values in .env file
sed -i "s/FPTN_HOST=.*/FPTN_HOST=$FPTN_HOST_GRAFANA/" .env
sed -i "s/FPTN_PORT=.*/FPTN_PORT=$FPTN_PORT_GRAFANA/" .env
sed -i "s/PROMETHEUS_SECRET_ACCESS_KEY=.*/PROMETHEUS_SECRET_ACCESS_KEY=$PROMETHEUS_SECRET_ACCESS_KEY/" .env

echo ".env файл для Grafana успешно настроен."
echo "Ваш секретный ключ для Prometheus: $PROMETHEUS_SECRET_ACCESS_KEY"
echo "Важно: убедитесь, что этот ключ совпадает с ключом в конфигурации вашего fptn-server (/etc/fptn/server.conf)."
echo ""

# Build and run Grafana
echo "Запуск Docker-контейнеров для Grafana..."
docker-compose down && docker-compose up -d

echo "Grafana успешно запущена!"
echo ""

# --- Final Instructions ---
echo "----------------------------------------------------"
echo "Установка завершена!"
echo "----------------------------------------------------"
echo "- Telegram-бот запущен в фоновом режиме."
echo "- Grafana доступна по адресу: http://$FPTN_HOST_GRAFANA:3000"
echo "  Логин/пароль по умолчанию: admin / admin (обязательно смените пароль после первого входа)."
echo ""
echo "Для остановки сервисов используйте 'docker-compose down' в соответствующих директориях:"
echo "- sysadmin-tools/telegram-bot"
echo "- sysadmin-tools/grafana"
echo "----------------------------------------------------"

exit 0
