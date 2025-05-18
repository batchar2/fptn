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
- Configure Server Information:
    - Set `FPTN_SERVER_HOST` with the actual host or IP address of your FPTN server.
    - Set `FPTN_SERVER_PORT` to the port number your FPTN server is listening on.
- Specify the Path to the Users File:
    - By default, the USERS_FILE variable is set to /etc/fptn/users.list. This path is usually appropriate and does not need to be changed unless you have specific requirements.
    - Ensure that this path is accessible from within the Docker container and has appropriate read/write permissions.

```bash
# Telegram bot API token
API_TOKEN=your_actual_api_token_here
````

**Welcome message for the bot (en)**

```bash
FPTN_WELCOME_MESSAGE_EN=...
```

**Welcome message for the bot (ru)**

FPTN_WELCOME_MESSAGE_RU = ....
"

**Maximum speed limit for users in Mbps.**

```bash
MAX_USER_SPEED_LIMIT=20
```

**Host or IP address of your FPTN server**

```bash
FPTN_SERVER_HOST=your-server-host-or-ip
```

**Port of your FPTN server**

```bash
FPTN_SERVER_PORT=your-server-port
```

**Path to the users file (default, not need to change by default)**

```bash
USERS_FILE=/etc/fptn/users.list
```


6. **🟢 Configure Public Servers**:

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

7. **🔴 Configure Servers for Censored Regions**:

Copy the demo configuration:

```bash
cp servers_censored_zone.json.demo servers_censored_zone.json
```

Then open `servers_censored_zone.json` and edit it the same way as `servers.json`, using server details intended for restricted or high-surveillance regions.


8. **Run the Bot**

After setting up the environment file, start the bot with:

```bash
docker compose build
docker compose up -d
```

This command will start the bot in detached mode, allowing it to run in the background.

9. **Stop the Bot**

To stop the bot, use:

```bash
docker compose down
```

This will stop and remove the running containers associated with your bot.

