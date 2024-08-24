#  FPTN 

[![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?style=for-the-badge\&logo=ubuntu\&logoColor=white)](https://github.com/batchar2/fptn/releases)
[![Mac OS](https://img.shields.io/badge/mac%20os-000000?style=for-the-badge\&logo=macos\&logoColor=F0F0F0)](https://github.com/batchar2/fptn/releases)
<!--
[![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge\&logo=windows\&logoColor=white)](https://github.com/batchar2/fptn/releases)
-->
[![Build and Test](https://github.com/batchar2/fptn/actions/workflows/main.yml/badge.svg)](https://github.com/batchar2/fptn/actions/workflows/main.yml)


  
FPTN is a VPN service designed to bypass censorship and access blocked content, particularly in ***heavily censored environments***.


FPTN operates by securely routing network traffic from your device through a VPN server to bypass censorship and access restricted content. The process involves encapsulating your traffic within a secure WebSocket tunnel, which is then processed by the VPN server. Here's a high-level overview of the workflow:

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









### FPTN Server Installation and Configuration

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
sudo systemctl start fptn-server
```

Check the server status with:
```bash
sudo systemctl status fptn-server
```














### FPTN Client Installation and Configuration

##### Step 1: Download FPTN Client

Download the FPTN client DEB package for your architecture (x86_64 or arm64) from [GitHub](https://github.com/batchar2/fptn/releases).



##### Step 2: Install the DEB Package

To install the FPTN client DEB package, run the following command in the terminal:
```bash
sudo apt install -f /path/to/fptn-client-cli.deb 
```

##### Step 3: Configure the Client
Open the client configuration file /etc/fptn-client/client.conf and set it up as follows:

```bash
# Configuration for fptn client
USERNAME=
PASSWORD=
NETWORK_INTERFACE=
VPN_SERVER_IP=
VPN_SERVER_PORT=443
GATEWAY_IP=
```

Configuration File Fields:
- `USERNAME` The username for authentication with the VPN server.
- `PASSWORD` The password associated with the username for VPN authentication.
NETWORK_INTERFACE The network interface on the client device to be used for VPN connections (e.g., eth0 or wlan0).
- `VPN_SERVER_IP` The IP address of the VPN server to connect to.
- `VPN_SERVER_PORT` The port number for the VPN server connection (default is 443).
- `GATEWAY_IP` The IP address of the gateway for the VPN connection (your router's address)

##### Step 4: Start the Client Service

To start the FPTN client service, use the following command:
```bash
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










  
<details>
  <summary>Build</summary>
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
conan install . --output-folder=build --build=missing  -s compiler.cppstd=17
cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build .
ctest
# to install in system
make install
```

Or GUI version

git submodule update --init --recursive
```bash
conan install . --output-folder=build --build=missing  -s compiler.cppstd=17 -o with_gui_client=True 
# or 
# conan install . --output-folder=build --build=missing -o with_gui_client=True -c tools.system.package_manager:mode=install

cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build .
ctest
# to install in system
make install
```

After that you can build deb (only on ubuntu)

```bash
cmake --build . --target build-deb
# or with UI
cmake --build . --target build-deb-gui
```

or build MacOS (only MacOs)

```bash
cmake --build . --target build-pkg
```


</details>


<details>
  <summary>Running server</summary>

1. Generate sertificate

```
mkdir keys
cd keys
openssl genrsa -out server.key 2048
openssl req -new -x509 -key server.key -out server.crt -days 365
openssl rsa -in server.key -pubout -out server.pub
cd ..
```

2. Create users

To add a new user to the VPN server with a specified bandwidth limit, use the following command:
```
sudo fptn-passwd --add-user user10 --bandwidth 30
```
Options:
- `--add-user`: The username for the new user. Example: user10.
- `--bandwidth`: The bandwidth limit for the user in megabits per second (Mbps). Example: 30.

3. Start the Server:
    
To start the server, use:
```
sudo fptn-server --server-crt=keys/server.crt --server-key=keys/server.key --out-network-interface=eth0 --server-pub=keys/server.pub
 ``` 
Options:
- `--server-crt`: Path to the server certificate file. Example: keys/server.crt.
- `--server-key`: Path to the server private key file. Example: keys/server.key.
- `--out-network-interface`: The network interface to use for outbound traffic. Example: eth0.
- `--server-pub`: Path to the server public key file. Example: keys/server.pub.
</details>


<details>
  <summary>Start the client</summary>  

To start the client, use the following command:
```
fptn-client --out-network-interface=en0  --vpn-server-ip="170.64.148.142" --username=user10 --password=user10
```
Options:
-  `--vpn-server-ip`: The IP address of the VPN server you want to connect to. Example: "170.64.148.142".
-  `--out-network-interface`: The network interface to use for outbound traffic. Example: en0 (typically used for Ethernet or Wi-Fi on macOS).
-  `--username`: The username for VPN authentication. Example: user10.
-  `--password`: The password for VPN authentication. Example: user10.

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



<details>
  <summary>MacOS</summary>
  
Solution: https://github.com/ntop/n2n/issues/773

- Download https://github.com/Tunnelblick/Tunnelblick/tree/master/third_party/tap-notarized.kext
- Download https://github.com/Tunnelblick/Tunnelblick/tree/master/third_party/tun-notarized.kext
- Change the name to tap.kext and tap.kext,
- Copy to /Library/Extensions
- add net.tunnelblick.tap.plist and net.tunnelblick.tun.plist to /Library/LaunchDaemons/

``` 
#net.tunnelblick.tap.plist
<?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
  <plist version="1.0">
  <dict>
      <key>Label</key>
      <string>net.tunnelblick.tap</string>
      <key>ProgramArguments</key>
      <array>
          <string>/sbin/kextload</string>
          <string>/Library/Extensions/tap.kext</string>
      </array>
      <key>KeepAlive</key>
      <false/>
      <key>RunAtLoad</key>
      <true/>
      <key>UserName</key>
      <string>root</string>
  </dict>
  </plist>
   #net.tunnelblick.tun.plist
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
  <plist version="1.0">
  <dict>
      <key>Label</key>
      <string>net.tunnelblick.tun</string>
      <key>ProgramArguments</key>
      <array>
          <string>/sbin/kextload</string>
          <string>/Library/Extensions/tun.kext</string>
      </array>
      <key>KeepAlive</key>
      <false/>
      <key>RunAtLoad</key>
      <true/>
      <key>UserName</key>
      <string>root</string>
  </dict>
</plist>
````

Run sudo kextload /Library/Extensions/tap.kext in the terminal
restart Mac after allowing the security check.


</details>

