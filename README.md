#  FPTN

[![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?style=for-the-badge\&logo=ubuntu\&logoColor=white)](https://github.com/batchar2/fptn/releases)
[![Mac OS](https://img.shields.io/badge/mac%20os-000000?style=for-the-badge\&logo=macos\&logoColor=F0F0F0)](https://github.com/batchar2/fptn/releases)
[![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge\&logo=windows\&logoColor=white)](https://github.com/batchar2/fptn/releases)


[![Build and Test](https://github.com/batchar2/fptn/actions/workflows/main.yml/badge.svg)](https://github.com/batchar2/fptn/actions/workflows/main.yml)


FPTN is a VPN service specifically designed to bypass censorship.
Initially launched as a research project, FPTN actively helps people gain access to a free internet.


FPTN operates by securely routing network traffic from your device through a VPN server to bypass censorship and access restricted content. 
The process involves encapsulating your traffic within a secure WebSocket tunnel, which is then processed by the VPN server. Here's a high-level overview of the workflow:

```
+--------------------+                      +--------------------+
|                    |                      |                    |
|    Client          |                      |    Server          |
|                    |                      |                    |
|  +-------------+   |                      |  +-------------+   |
|  |             |   |    HTTPS WebSocket   |  |             |   |
|  | VPN Client  +   +<-------------------->+  | VPN Server  |   |
|  |             |   |                      |  |             |   |
|  +-------------+   |                      |  +-------------+   |
|                    |                      |                    |
+--------------------+                      +--------------------+
      ^                                         ^
      |                                         |
      |                                         |
      |                                         |
      v                                         v
+--------------------+                      +--------------------+
|                    |                      |                    |
|   Traffic          |                      |   Traffic          |
|                    |                      |                    |
+--------------------+                      +--------------------+
```

FPTN can be seamlessly integrated with **NGINX**, allowing you to disguise the VPN server behind any regular web server. This can be particularly useful in evading detection and bypassing restrictive network filters. By using NGINX to proxy WebSocket connections, you can effectively hide the VPN server behind the facade of a regular website.




### FPTN Client Installation and Setup

*🍏🍎For MacOS users, please refer to the [macOS installation guide](docs/macos/README.md) for detailed instructions, as macOS has additional security measures that may require special steps.*

Download the FPTN client from [WebSite](http://batchar2.github.io/fptn/) or [GitHub](https://github.com/batchar2/fptn/releases). After downloading, install and run the client.

FPTN Client is a straightforward application with an interface located in the system tray.
Once the client is running, find the VPN client icon in the system tray.

Simply click on the icon to open the context menu.

<img style="max-height: 200px" class="img-center" src="docs/images/client.png" alt="Application"/>


Open "Settings" to configure your client.

Registration for accessing the free internet via FPTN is very simple!
Use our Telegram bot [@fptn_bot](https://t.me/fptn_bot),
which will quickly provide you with the parameters for internet access.

Open the settings to add a new connection. To do this, download the file provided by
the bot and simply upload it in your client's settings by clicking the "Load config" button.

<img style="max-height: 350px" src="docs/images/settings-2.png" alt="Settings"/>
                       

After that, save the settings.
<img style="max-height: 350px" src="docs/images/settings-3.png" alt="Settings"/>
                       
Ease of use:
<img style="max-height: 350px" class="img-center" src="docs/images/running-client.png" alt="Settings"/>

You can also easily turn your Raspberry Pi or Orange Pi into a WiFi access point and install the FPTN client on it.
In this case, all devices connected to the WiFi will be able to access the internet, bypassing any restrictions.
[Read more here](https://github.com/batchar2/fptn/blob/master/deploy/linux/wifi/README.md)


<img style="max-height: 350px" src="docs/images/orangepi.jpg" alt="Settings"/>







<details>
  <summary>FPTN Server Installation and Configuration</summary>

##### Step 1: Download FPTN from GitHub
Download the FPTN server DEB package for your architecture (x86_64 or arm64) from [GitHub](https://github.com/batchar2/fptn/releases).

##### Step 2: Install the DEB Package

To install the FPTN server DEB package, consider your processor architecture (ADM or ARM). Run the following command in the terminal:

```bash
sudo apt install -f /path/to/fptn-server.deb 
```

##### Step 3: Generate sertificate

Navigate to the /etc/fptn/ directory:
```bash
cd /etc/fptn/
```

Generate the required keys using OpenSSL:

```bash
openssl genrsa -out server.key 2048
openssl req -new -x509 -key server.key -out server.crt -days 365
openssl rsa -in server.key -pubout -out server.pub
```

##### Step 4: Configure the Server

Open the server configuration file /etc/fptn/server.conf and set it up as follows:

```bash
# Configuration for fptn server

OUT_NETWORK_INTERFACE=eth0

# KEYS
SERVER_KEY=server.key
SERVER_CRT=server.crt
SERVER_PUB=server.pub

PORT=443
TUN_INTERFACE_NAME=fptn0

LOG_FILE=/var/log/fptn-server.log
```

Configuration File Fields
- `OUT_NETWORK_INTERFACE` Specifies the network interface that the server will use for outgoing traffic (e.g., eth0 for Ethernet). Ensure this is set to the correct network interface on your system.
- `SERVER_KEY` The filename of the private key for the server. This key is used for encrypting and signing communications.
- `SERVER_CRT` The filename of the server's SSL certificate. This certificate is used to establish a secure connection between the server and clients.
- `SERVER_PUB` The filename of the public key derived from the private key. This is used by clients to verify the server's identity.
- `PORT` The port number on which the server will listen for incoming connections (e.g., 443). Ensure this port is open and not in use by other services.
- `TUN_INTERFACE_NAME` The name of the virtual network interface used by the VPN (e.g., fptn0). This interface is used for tunneling VPN traffic.
- `LOG_FILE` The path to the log file where server logs will be written (e.g., /var/log/fptn-server.log). This file is useful for troubleshooting and monitoring server activity.

##### Step 5: Add User

Before restarting the server, add a user with bandwidth limits. Use the following command:

```bash
sudo fptn-passwd --add-user user10 --bandwidth 30
```

This command adds a user named user10 and sets a bandwidth limit of 30 MB for this user.

##### Step 7: Start the Server

To start the server, use the following command:
```bash
sudo systemctl enable fptn-server
sudo systemctl start fptn-server
```

Check the server status with:
```bash

sudo systemctl status fptn-server
```

##### Step 8: DNS

To configure a `DNS server` using `dnsmasq`, follow these steps:

1. Install dnsmasq

Install the dnsmasq package using the following command:


```bash
sudo apt update
sudo apt install dnsmasq
```


2. Additional settings for systemd

If you are using Ubuntu 24.04/22.04, follow these additional steps:

Open the file `/etc/systemd/resolved.conf`

Find the DNSStubListener parameter, uncomment it, and change the value to no:

```bash
DNSStubListener=no
``` 

Restart the systemd-resolved service:

```bash
sudo systemctl restart systemd-resolved
```



3. Configure dnsmasq

Open the dnsmasq configuration file `/etc/dnsmasq.conf`

Add or modify the following line to set up DNS forwarding to Google's public DNS server:

```bash
server=8.8.8.8
```

4. Restart dnsmasq

Apply the changes by restarting the dnsmasq service:


```
sudo systemctl restart dnsmasq
```

5. Verify the Configuration

Check the status of dnsmasq to ensure it is running correctly:

```
sudo systemctl status dnsmasq
```

You can also test DNS resolution to confirm that the server is working:

```
dig @127.0.0.1 google.com
```


##### Step 9. Telegram and Grafana

Please follow the instructions for setting up both the [Telegram bot](sysadmin-tools/telegram-bot/README.md) and [Grafana](sysadmin-tools/grafana/README.md).
With these tools, you can run your own bot and monitoring system.

<img src="sysadmin-tools/grafana/images/grafana-1.jpg" alt="Grafana"/>


</details>

<details>
  <summary>FPTN Console Client Installation and Configuration</summary>  

##### Step 1. Download the FPTN client-cli

Download the FPTN client cli DEB package for your architecture (x86_64 or arm64) from [WebSite](http://batchar2.github.io/fptn/) or [GitHub](https://github.com/batchar2/fptn/releases).

##### Step 3. Get access file

Use our [Telegram bot](https://t.me/fptn_bot), to quickly obtain your access file for internet connectivity.

##### Step 3: Install the DEB Package

To install the FPTN client DEB package, run the following command in the terminal:
```bash
sudo apt install -f /path/to/fptn-client-cli.deb 
```

##### Step 4. Run in Command Line
Using the user credentials created in the previous step, try to connect via the command line:

```bash
fptn-client-cli --access-config=/path/to/config.fptn
```

*In some situations, you may need to specify your network gateway IP (e.g., router IP) using the `--gateway-ip` option when the client cannot automatically detect it 
or `--out-network-interface` option to set the specific network interface to be used.*

##### Step 5 (Optional): Configure the Client

You can run fptn-client as a systemd service. To do this, open the client configuration file at `/etc/fptn-client/client.conf` and set it up as follows:

```bash
# Configuration for FPTN client (required)
ACCESS_CONFIG=

# Optional: Specify the network interface
NETWORK_INTERFACE=

# Optional: Specify the gateway IP (e.g., router IP)
GATEWAY_IP=
```

Configuration File Fields:
- `ACCESS_CONFIG` Path to access file.
- `NETWORK_INTERFACE` (Optional) The network interface on the client device to be used for VPN connections (e.g., eth0 or wlan0).
- `GATEWAY_IP` (Optional) The IP address of the gateway for the VPN connection (your router's address)

##### Step 6 (Optional): Start the Client Service

To start the FPTN client service, use the following command:
```bash
sudo systemctl enable fptn-client
sudo systemctl start fptn-client
```

Check the client service status with:

```bash
sudo systemctl status fptn-client
```

Logs for the client service will be written to the system journal. You can view logs with:
```bash
journalctl -u fptn-client
```

</details>




  
<details>
  <summary>How to build</summary>
1. Install Conan (version 2.3.2):

```
pip install conan==2.3.2
sudo apt install gcc g++ cmake pkg-config
```

  

2. Detect and configure Conan profile:

```
conan profile detect --force
```

  
3. Install dependencies, build and install:


Console version

```bash
git submodule update --init --recursive 
conan install . --output-folder=build --build=missing  -s compiler.cppstd=17 --settings build_type=Release
cd build
# only linux & macos
cmake .. -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release
# only windows 
cmake .. -G "Visual Studio 17 2022" -DCMAKE_TOOLCHAIN_FILE="conan_toolchain.cmake" -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
ctest
# to install in system
make install
```

Or GUI version



<details>
  <summary>For build on Ubuntu, install the following packages:</summary>

```bash
sudo apt-get update
sudo apt-get install -y libx11-dev libx11-xcb-dev libfontenc-dev libice-dev libsm-dev libxau-dev libxaw7-dev \
libxcomposite-dev libxcursor-dev libxdamage-dev libxfixes-dev libxi-dev libxinerama-dev libxkbfile-dev \
libxmuu-dev libxrandr-dev libxrender-dev libxres-dev libxss-dev libxtst-dev libxv-dev libxxf86vm-dev \
libxcb-glx0-dev libxcb-render0-dev libxcb-render-util0-dev libxcb-xkb-dev libxcb-icccm4-dev libxcb-image0-dev \
libxcb-keysyms1-dev libxcb-randr0-dev libxcb-shape0-dev libxcb-sync-dev libxcb-xfixes0-dev libxcb-xinerama0-dev \
libxcb-dri3-dev uuid-dev libxcb-cursor-dev libxcb-dri2-0-dev libxcb-dri3-dev libxcb-present-dev libxcb-composite0-dev \
libxcb-ewmh-dev libxcb-res0-dev libxcb-util-dev pkg-config libgl-dev libgl1-mesa-dev
```

</details>

```bash
git submodule update --init --recursive

# Need a manual installation list of dependencies for Ubuntu.
conan install . --output-folder=build --build=missing  -s compiler.cppstd=17 -o with_gui_client=True --settings build_type=Release

cd build
# only linux & macos
cmake .. -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release
# only windows 
cmake .. -G "Visual Studio 17 2022" -DCMAKE_TOOLCHAIN_FILE="conan_toolchain.cmake" -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
ctest
# to install in system
make install
```

After that you can build deb (only on ubuntu)

```bash
cmake --build . --config Release --target build-deb
# or with UI
cmake --build . --config Release --target build-deb-gui
```

or build MacOS installer

```bash
cmake --build . --config Release --target build-pkg
```

or build Windows installer

```bash
cmake --build . --config Release --target build-installer
```

</details>

<details>
  <summary>Using CLion IDE</summary>
  
Run the following command in the project folder:

```
conan install . --output-folder=cmake-build-debug --build=missing -s compiler.cppstd=17 -o with_gui_client=True --settings build_type=Debug
```

Open the project in CLion. After opening the project, the "Open Project Wizard" will appear automatically. You need to add the following CMake option:

```
-DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake
```

</details>
