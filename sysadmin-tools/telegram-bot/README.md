## Telegram Bot

This guide will help you build, configure, and run your Telegram bot using Docker.

0. **Prerequisites**

Docker and Docker Compose should be installed on your system. To install it on ubuntu use [this docs](https://docs.docker.com/engine/install/ubuntu/)

1. **Clone the repository:**

Clone the repository to any location on your server:

```bash
git clone https://github.com/batchar2/fptn.git
```

2. **Navigate to the Grafana configuration folder:**

```bash
cd sysadmin-tools/telegram-bot
```

3. **Build the Bot**

To build the Docker image for your Telegram bot, run the following command:

```
docker compose build
```


4. **Create the Configuration File:**

Copy the example environment file and rename it:

```bash
cp .env.demo .env
```

5. **Edit the .env File**:

To configure your bot, you'll need to edit the .env file. This file contains sensitive information required for the bot to function properly. Follow these steps to set it up:

-  Open the .env File:
    - Use a text editor to open the .env file. You can find this file in the root directory of your project.
- Insert Your Bot's API Token:
    - Set `TELEGRAM_API_TOKEN` environment variable with your Telegram bot API token. This token is required for the bot to connect to Telegram's servers. You can obtain your API token from Telegram by using the [BotFather](https://t.me/BotFather) bot.
- Set the Welcome Message (Optional):
    - Modify the `FPTN_WELCOME_MESSAGE` variable to customize the greeting message that your bot will send to users.
- Set Maximum User Speed Limit:
    - Modify the `MAX_USER_SPEED_LIMIT` variable to define the maximum speed limit for users in megabits per second (Mbps). This setting controls the bandwidth cap applied to individual users. Adjust the value based on your requirements.
- Configure Service Name:
  - Set `SERVICE_NAME` to your preferred service name (appears in logs and messages).
- Enable Brotli Compression:
  - Set `ENABLE_BROTLI_COMPRESSION` to `true` for smaller tokens or `false` to disable.
- Configure Configuration Folder Path:
  Set `FPTN_CONFIGS_FOLDER` to specify the directory where all configuration files are stored.
  - Default value: `./configs` (relative path to the project root)
  - Alternative: Use an absolute path like `/etc/fptn` to point to the folder where the FPTN server keeps user data
  - This folder will be mounted to `/etc/fptn` inside the Docker container
  - **All configuration files must be placed in this directory:**
    - `servers.json` - public servers list
    - `servers_censored_zone.json` - censored region servers
    - `users.list` - user database
    - `premium_servers.json` - premium servers (optional)

Example `.env` configuration:

```bash
# Telegram bot API token
TELEGRAM_API_TOKEN=your_actual_api_token_here

# Welcome messages for the bot
FPTN_WELCOME_MESSAGE_EN = "⚡ Welcome to the FPTN bot! ⚡ \n
Use this bot to get a VPN access token or reset it. \n\n
🌐_ You can download the client from the official project website _ [https://storage.googleapis.com/fptn.org/index.html](https://storage.googleapis.com/fptn.org/index.html) \n\n
👉_ To get your connection token, just type the command: _ /token \n
"

FPTN_WELCOME_MESSAGE_RU = "⚡ Добро пожаловать в бот FPTN! ⚡ \n
Этот бот позволяет получить токен доступа к VPN или сбросить его. \n\n
🌐_ Клиент можно скачать с официального сайта проекта _ [https://storage.googleapis.com/fptn.org/index.html](https://storage.googleapis.com/fptn.org/index.html) \n\n
👉_ Чтобы получить токен для подключения, просто введите команду: _ /token \n
"

# Enable Brotli compression for smaller tokens
ENABLE_BROTLI_COMPRESSION=true

# Maximum speed limit for new users in Mbps.
MAX_USER_SPEED_LIMIT=20

# name of service
SERVICE_NAME=FPTN.ONLINE


# Path to the FPTN configuration folder on the host machine
# This folder will be mounted to /etc/fptn inside the container
# Recommended: ./configs (relative path) or /etc/fptn (absolute path)
# Create this folder and place all config files here:
# - servers.json
# - servers_censored_zone.json
# - users.list
# - premium_servers.json
FPTN_CONFIGS_FOLDER=./configs

```

6. **Initialize Configuration Folder**

   Important: Before running the bot, you must set up the configuration folder and populate it with necessary files.

```bash
# Create the configuration folder (matches FPTN_CONFIGS_FOLDER in .env)
cd ./configs

# Copy demo server configurations to the config folder
cp servers.json.demo servers.json
cp premium_servers.json.demo premium_servers.json
cp servers_censored_zone.json.demo servers_censored_zone.json

# Create empty required files
touch ./configs/users.list
touch ./configs/premium_servers.json

# Verify the folder structure
ls -la ./configs/
```

Expected folder structure after setup:

```bash
telegram-bot/
├── docker-compose.yml
├── .env
├── Dockerfile
├── logs/
└── configs/                       # ← ALL CONFIGURATION FILES HERE
    ├── servers.json               # Public servers list
    ├── servers_censored_zone.json # Censored region servers
    ├── premium_servers.json       # Premium servers list
    └── users.list                 # User database
```


7. **🟢 Configure Public Servers**:

To set up your server list, follow these steps:

Start by copying the demo server list:

```bash
cp servers.json.demo server.json
```

Then open `servers.json` in any text editor and replace the example entries with your actual server information:

- name: A label for your server (any value).
- host: The public IP address or hostname of your server.
- port: The public port your VPN server listens on.
- md5_fingerprint: The MD5 fingerprint of your server's TLS certificate.

To get the fingerprint, run this command on the server:

```bash
openssl x509 -noout -fingerprint -md5 -in /etc/fptn/server.crt | cut -d'=' -f2 | tr -d ':' | tr 'A-F' 'a-f'
```

Copy the value and paste it into the md5_fingerprint field.

8. **🔴 Configure Servers for Censored Regions**:

Copy the demo configuration:

```bash
cp servers_censored_zone.json.demo servers_censored_zone.json
```

Then open `servers_censored_zone.json` and edit it the same way as `servers.json`, using server details intended for restricted or high-surveillance regions.

9. **⚡ Configure Premium Servers**:


- Premium servers have the same structure as regular servers

- These servers are only accessible to premium users

- Can be used for higher speeds, special locations, or better performance


10. **Premium User Identification in `users.list` File**

Premium users are identified by a special flag in the users.list file. Here's how it works:

File Format. Each line in users.list follows this format:

```bash
username password_hash speed_limit premium_flag
...
user00001 213098467123094612309846 100 1
user00002 321o32908237249384233232 100 0
```

Premium Flag Values:
- 0 = Regular user (not premium)
- 1 = Premium user


10. **Run the Bot**

After setting up the environment file, start the bot with:

```bash
docker compose build
docker compose up -d
```

This command will start the bot in detached mode, allowing it to run in the background.

11. **Stop the Bot**

To stop the bot, use:

```bash
docker compose down
```

This will stop and remove the running containers associated with your bot.

