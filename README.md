#  FPTN (FuckOffPutin-VPN)

  
FPTN (FuckOffPutin-VPN) is a VPN service designed to bypass censorship and access blocked content, particularly in ***heavily censored environments*** like Russia and other countries.

  

##  Description

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

FPTN can be seamlessly integrated with **NGINX**, allowing you to disguise the VPN server behind any regular web server. This can be particularly useful in evading detection and bypassing restrictive network filters. By using NGINX to proxy WebSocket connections, you can effectively hide the VPN server behind the façade of a regular website.


```
    location /fptn/ {
        proxy_pass http://localhost:YOUR_VPN_SERVER_PORT; # Replace with the port where your VPN server is running
        proxy_http_version 1.1;

        # Upgrade the connection to WebSocket
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';

        # Pass necessary headers to the VPN server
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Optional: Set timeouts to ensure stable connections
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
    }
```


**This method makes it significantly harder for censorship systems to identify and block your VPN traffic.** Since the VPN traffic is disguised as standard web traffic, filtering mechanisms that focus on identifying specific VPN protocols or patterns will struggle to detect and block this traffic. Consequently, the VPN becomes more resilient against censorship and filtering attempts, improving access to restricted content in heavily censored environments.

##  Features

-  Bypasses government censorship and blocks.
-  Encrypts internet traffic to ensure privacy.
-  Easy to use and setup?
  
##  Build Instructions

  

###  Prerequisites

  

-  Python 3.x

-  Conan package manager
- g++
- gcc
- cmake

  
  

###  Installation

  

1. Install Conan (version 2.3.2):

```
pip install conan==2.3.2
sudo apt install gcc g++ cmake
```

  

2. Detect and configure Conan profile:

```
conan profile detect --force
```

  
3. Install dependencies and build:

```
git submodule update --init --recursive 

conan install . --output-folder=build --build=missing
conan build . --output-folder=build
```

  

###  Generate sertificate

```
mkdir keys
cd keys
openssl genrsa -out server.key 2048
openssl req -new -x509 -key server.key -out server.crt -days 365
openssl rsa -in server.key -pubout -out server.pub
cd ..
```

### Running the Server

##### Start the Server:
    
To start the server, use:
```
sudo build/build/Release/code/server/fptn-server --server-crt=keys/server.crt --server-key=keys/server.key --out-network-interface=eth0 --tun-interface-address=2.2.0.1
 ``` 
 -  --server-port: The port where the server will listen (e.g.,  8080).
 -  --interface-address: The IP address of the interface (e.g.,  1.1.1.1).
 -  --interface-name: The name of the network interface (e.g.,  tun0).
 -  --server-crt: Path to the server's certificate file (e.g.,  ./keys/server.crt).
 -  --server-key: Path to the server's key file (e.g.,  ./keys/server.key).
##### Set Up the Server Configuration:
Open a new terminal and run the setup script while keeping the server running. Here’s what each argument means:

``` 
sudo code/server/scripts/server-network-setup.sh <network_interface>
``` 
-   <network_interface>: The network interface you want to use (e.g.,  eth0).
    
Example:
```
sudo code/server/scripts/server-network-setup.sh eth0
```

### Running client

##### Start the client:

When your URI contains your address, run:
```
sudo cmake-build-debug/build/Release/code/client/fptn-client --vpn-server-uri="wss://170.64.148.141:8080/fptn" --out-network-interface=en0 --tun-interface-name=tun0 --gateway-ip=192.168.4.1
```

##### Set up the configuration:

Open a new terminal and run the configuration script. Keep the client running in the other terminal:
and after that need to run configuration script, in diferent terminal and do not stop client

```
sudo code/client/scipts/linux-client-network-setup.sh <external_interface>  <gateway_ip>  <vpn_server_ip>
```
- <external_interface>: The network interface used to route traffic to the VPN server (e.g., enp0s5).
- <gateway_ip>: The IP address of the gateway for the external interface (e.g., 10.211.55.1).
- <vpn_server_ip>: The IP address of the VPN server (e.g., 170.64.148.141).

  

My example:
```
sudo code/client/scipts/client-network-setup.sh enp0s5 10.211.55.1 170.64.148.141
```


#### Using CLion IDE

After opening the project, the "Open Project Wizard" will appear automatically. You need to add the following CMake options:

```
-DCONAN_HOST_PROFILE="auto-cmake;default" -DCMAKE_PROJECT_TOP_LEVEL_INCLUDES=./conan_provider.cmake
```


#### MacOS 

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



```
sudo code/client/scipts/macos-client-network-setup.sh en0 192.168.4.1 170.64.148.141
```