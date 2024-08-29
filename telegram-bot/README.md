## Telegram Bot

This guide will help you build, configure, and run your Telegram bot using Docker.

### Prerequisites

Docker and Docker Compose should be installed on your system.

### Build the Bot

To build the Docker image for your Telegram bot, run the following command:

```
docker-compose build
```

### Configure the Bot

##### 1. Create the Configuration File:

Copy the example environment file and rename it:

```bash
cp .env.demo .env
```

##### 2. Edit the .env File:

To configure your bot, you'll need to edit the .env file. This file contains sensitive information required for the bot to function properly. Follow these steps to set it up:

-  Open the .env File:
    - Use a text editor to open the .env file. You can find this file in the root directory of your project.
  - Insert Your Bot's API Token:
    - Set `TELEGRAM_API_TOKEN`  with your Telegram bot API token. This token allows the bot to connect to Telegram's servers.
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


# Welcome message for the bot
FPTN_WELCOME_MESSAGE="⚡⚡⚡ Welcome to the FPTN service bot! ⚡⚡⚡\n\n
This bot allows you to get access to VPN services or restore your password.\n
How can I assist you today?"


# Maximum speed limit for users in Mbps.
MAX_USER_SPEED_LIMIT=20


# Host or IP address of your FPTN server
FPTN_SERVER_HOST=your-server-host-or-ip


# Port of your FPTN server
FPTN_SERVER_PORT=your-server-port


# Path to the users file (default, not need to change by default)
USERS_FILE=/etc/fptn/users.list
````

### Run the Bot

After setting up the environment file, start the bot with:

```bash
docker-compose up -d
```

This command will start the bot in detached mode, allowing it to run in the background.

### Stop the Bot

To stop the bot, use:

```bash
docker-compose down
```

This will stop and remove the running containers associated with your bot.

