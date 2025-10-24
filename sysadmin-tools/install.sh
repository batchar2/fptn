#!/bin/bash

# --- Helper Functions ---

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to print a separator line
print_separator() {
    echo "----------------------------------------------------"
}

# Function to print a header for a section
print_header() {
    print_separator
    echo "$1"
    print_separator
}

# --- Main Script ---

# Set script directory
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# --- Welcome Message ---
print_header "Добро пожаловать в скрипт автоматической установки!"
echo "Этот скрипт поможет вам настроить и запустить"
echo "FPTN-сервер, Telegram-бота и Grafana для мониторинга."
echo ""

# --- Dependency Checks ---
print_header "Проверка зависимостей..."
DEPS=("docker" "docker-compose" "curl" "jq" "openssl" "git")
for dep in "${DEPS[@]}"; do
    if ! command_exists "$dep"; then
        echo "Ошибка: '$dep' не найден. Пожалуйста, установите его."
        # Provide installation instructions for common cases
        if [[ "$dep" == "docker" || "$dep" == "docker-compose" ]]; then
            echo "Инструкция по установке Docker: https://docs.docker.com/engine/install/ubuntu/"
        elif [[ "$dep" == "jq" ]]; then
            echo "Вы можете установить его командой: sudo apt-get install jq"
        fi
        exit 1
    fi
done
echo "Все необходимые зависимости найдены."
echo ""

# --- Gather User Input ---
print_header "Сбор необходимых данных"
read -p "Хотите установить FPTN-сервер на этой машине? (y/n): " INSTALL_FPTN_SERVER
read -p "Введите публичный IP-адрес этого сервера: " PUBLIC_IP
read -p "Введите API-токен вашего Telegram-бота: " TELEGRAM_API_TOKEN

# Generate a random secret key for Prometheus once
PROMETHEUS_SECRET_ACCESS_KEY=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32 ; echo '')
echo ""
echo "Секретный ключ для Prometheus сгенерирован: $PROMETHEUS_SECRET_ACCESS_KEY"
echo "Он будет использован для настройки FPTN-сервера и Grafana."
echo ""


# --- FPTN Server Installation ---
if [[ "$INSTALL_FPTN_SERVER" =~ ^[Yy]$ ]]; then
    print_header "Установка FPTN-сервера"

    # 1. Determine architecture and latest version
    ARCH=$(dpkg --print-architecture)
    if [ "$ARCH" = "amd64" ]; then
        echo "Определена архитектура: amd64"
    elif [ "$ARCH" = "arm64" ]; then
        echo "Определена архитектура: arm64"
    else
        echo "Ошибка: неподдерживаемая архитектура '$ARCH'."
        exit 1
    fi

    # 1a. Get repository URL from git and set fallback
    ORIGINAL_REPO="batchar2/fptn"
    GIT_URL=$(git config --get remote.origin.url)
    REPO_PATH=$(echo "$GIT_URL" | sed -E 's/https?:\/\/github.com\/(.*).git/\1/')
    if [ -z "$REPO_PATH" ]; then
        echo "Предупреждение: не удалось определить репозиторий GitHub из 'git remote'. Используется репозиторий по умолчанию: $ORIGINAL_REPO"
        REPO_PATH=$ORIGINAL_REPO
    else
        echo "Репозиторий определен как: $REPO_PATH"
    fi

    LATEST_TAG=$(curl -s "https://api.github.com/repos/$REPO_PATH/releases/latest" | jq -r .tag_name)
    if [ -z "$LATEST_TAG" ] || [ "$LATEST_TAG" = "null" ]; then
        echo "В репозитории '$REPO_PATH' не найдены релизы."
        echo "Попытка получить релиз из основного репозитория: $ORIGINAL_REPO"
        REPO_PATH=$ORIGINAL_REPO
        LATEST_TAG=$(curl -s "https://api.github.com/repos/$REPO_PATH/releases/latest" | jq -r .tag_name)
        if [ -z "$LATEST_TAG" ] || [ "$LATEST_TAG" = "null" ]; then
            echo "Ошибка: не удалось найти релизы и в основном репозитории '$REPO_PATH'."
            exit 1
        fi
    fi
    echo "Последняя версия FPTN: $LATEST_TAG"

    # 2. Download and install .deb package
    DEB_NAME="fptn-server-${LATEST_TAG}-ubuntu22.04-${ARCH}.deb"
    DOWNLOAD_URL="https://github.com/$REPO_PATH/releases/download/$LATEST_TAG/$DEB_NAME"
    echo "Загрузка пакета: $DOWNLOAD_URL"
    curl -L -o "$DEB_NAME" "$DOWNLOAD_URL"
    echo "Установка пакета..."
    sudo apt-get update && sudo apt-get install -y -f "./$DEB_NAME"
    rm "$DEB_NAME"
    echo "Пакет FPTN-сервера успешно установлен."

    # 3. Generate certificates
    echo "Генерация SSL-сертификатов..."
    sudo mkdir -p /etc/fptn
    cd /etc/fptn || exit 1
    sudo openssl genrsa -out server.key 2048
    sudo openssl req -new -x509 -key server.key -out server.crt -days 365 -subj "/CN=$PUBLIC_IP"
    sudo openssl rsa -in server.key -pubout -out server.pub
    cd "$SCRIPT_DIR" || exit 1
    echo "Сертификаты успешно сгенерированы."

    # 4. Configure server
    read -p "Введите имя исходящего сетевого интерфейса (например, eth0): " OUT_NETWORK_INTERFACE
    echo "Настройка /etc/fptn/server.conf..."
    sudo sed -i "s/OUT_NETWORK_INTERFACE=.*/OUT_NETWORK_INTERFACE=$OUT_NETWORK_INTERFACE/" /etc/fptn/server.conf
    sudo sed -i "s|SERVER_KEY=.*|SERVER_KEY=/etc/fptn/server.key|" /etc/fptn/server.conf
    sudo sed -i "s|SERVER_CRT=.*|SERVER_CRT=/etc/fptn/server.crt|" /etc/fptn/server.conf
    sudo sed -i "s|SERVER_PUB=.*|SERVER_PUB=/etc/fptn/server.pub|" /etc/fptn/server.conf
    sudo sed -i "s/PROMETHEUS_SECRET_ACCESS_KEY=.*/PROMETHEUS_SECRET_ACCESS_KEY=$PROMETHEUS_SECRET_ACCESS_KEY/" /etc/fptn/server.conf
    echo "Конфигурация сервера обновлена."

    # 5. Add user
    print_header "Создание пользователя FPTN"
    read -p "Введите имя нового пользователя: " FPTN_USER
    read -sp "Введите пароль для нового пользователя: " FPTN_PASSWORD
    echo ""
    read -p "Введите ограничение скорости для пользователя (в Мбит/с): " FPTN_BANDWIDTH
    sudo fptn-passwd --add-user "$FPTN_USER" --password "$FPTN_PASSWORD" --bandwidth "$FPTN_BANDWIDTH"
    echo "Пользователь '$FPTN_USER' успешно создан."

    # 6. Configure dnsmasq
    echo "Установка и настройка dnsmasq..."
    sudo apt-get install -y dnsmasq
    echo "server=8.8.8.8" | sudo tee -a /etc/dnsmasq.conf
    echo "server=8.8.4.4" | sudo tee -a /etc/dnsmasq.conf
    # Handle systemd-resolved conflict
    if sudo systemctl is-active --quiet systemd-resolved; then
        sudo sed -i 's/#DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf
        sudo systemctl restart systemd-resolved
    fi
    sudo systemctl enable dnsmasq
    sudo systemctl restart dnsmasq
    echo "dnsmasq настроен."

    # 7. Start FPTN server
    echo "Запуск FPTN-сервера..."
    sudo systemctl enable fptn-server
    sudo systemctl start fptn-server
    sudo systemctl status fptn-server
fi

# --- Configure Telegram Bot ---
print_header "Настройка Telegram-бота"
cd "$SCRIPT_DIR/telegram-bot" || { echo "Ошибка: не удалось найти директорию telegram-bot"; exit 1; }
cp .env.demo .env
sed -i "s/API_TOKEN=.*/API_TOKEN=$TELEGRAM_API_TOKEN/" .env
sed -i "s/FPTN_SERVER_HOST=.*/FPTN_SERVER_HOST=$PUBLIC_IP/" .env
sed -i "s/FPTN_SERVER_PORT=.*/FPTN_SERVER_PORT=443/" .env
echo ".env файл для бота успешно настроен."
cp servers.json.demo servers.json
cp servers_censored_zone.json.demo servers_censored_zone.json
echo "Важно: не забудьте отредактировать 'servers.json' и 'servers_censored_zone.json'!"
docker-compose build
docker-compose up -d
echo "Telegram-бот успешно запущен!"
echo ""

# --- Configure Grafana ---
print_header "Настройка Grafana"
cd "$SCRIPT_DIR/grafana" || { echo "Ошибка: не удалось найти директорию grafana"; exit 1; }
cp .env.demo .env
sed -i "s/FPTN_HOST=.*/FPTN_HOST=$PUBLIC_IP/" .env
sed -i "s/FPTN_PORT=.*/FPTN_PORT=443/" .env
sed -i "s/PROMETHEUS_SECRET_ACCESS_KEY=.*/PROMETHEUS_SECRET_ACCESS_KEY=$PROMETHEUS_SECRET_ACCESS_KEY/" .env
echo ".env файл для Grafana успешно настроен."
docker-compose down && docker-compose up -d
echo "Grafana успешно запущена!"
echo ""

# --- Final Instructions ---
print_header "Установка завершена!"
echo "- Telegram-бот запущен в фоновом режиме."
echo "- Grafana доступна по адресу: http://$PUBLIC_IP:3000"
echo "  Логин/пароль по умолчанию: admin / admin (обязательно смените пароль!)."

if [[ "$INSTALL_FPTN_SERVER" =~ ^[Yy]$ ]]; then
    echo "- FPTN-сервер запущен и работает."

    # Generate and display user token
    FINGERPRINT=$(sudo openssl x509 -noout -fingerprint -md5 -in /etc/fptn/server.crt | cut -d'=' -f2 | tr -d ':' | tr 'A-F' 'a-f')
    JSON_CONFIG=$(jq -n \
                  --arg user "$FPTN_USER" \
                  --arg pass "$FPTN_PASSWORD" \
                  --arg ip "$PUBLIC_IP" \
                  --arg fp "$FINGERPRINT" \
                  '{version: 1, service_name: "MyFptnServer", username: $user, password: $pass, servers: [{name: "MyFptnServer", host: $ip, md5_fingerprint: $fp, port: 443}]}')

    BASE64_TOKEN=$(echo -n "$JSON_CONFIG" | base64 -w 0 | sed 's/=*$//')
    FINAL_TOKEN="fptn:$BASE64_TOKEN"

    print_separator
    echo "ВАШ ТОКЕН ДОСТУПА К FPTN-СЕРВЕРУ:"
    echo "$FINAL_TOKEN"
    print_separator
fi

echo ""
echo "Для остановки сервисов используйте 'docker-compose down' в директориях 'telegram-bot' и 'grafana'."
print_separator

exit 0
