### Setting Up a WiFi-VPN Access Point on Raspberry Pi

This guide outlines the process of setting up a WiFi access point on a Raspberry Pi or another computer with all traffic routed through a VPN. Follow the instructions to turn your Raspberry Pi into a full-fledged access point.

#### Step 1: Download VPN Client Version for ARM

Set up the VPN client according to [this section](https://github.com/batchar2/fptn?tab=readme-ov-file#fptn-client-installation-and-configuration).

#### Step 2: Install Required Packages

You will need the following packages to set up the access point:

```bash
sudo apt install hostapd dnsmasq
```

#### Step 3: System Configuration

Disable and stop the hostapd and dnsmasq services to avoid conflicts:

```bash
sudo systemctl stop hostapd
sudo systemctl disable hostapd
sudo systemctl stop dnsmasq
sudo systemctl disable dnsmasq
```


<details>
<summary>Additional Settings for Ubuntu 24.04</summary>

If you are using Ubuntu 24.04, follow these additional steps:

Open the file `/etc/systemd/resolved.conf`


Find the DNSStubListener parameter, uncomment it, and change the value to no:

```bash
DNSStubListener=no
``` 

Restart the systemd-resolved service:

```bash
sudo systemctl restart systemd-resolved
```

Reboot your system:

```bash
sudo reboot
```

</details>




#### Step 4: Configure Hostapd

Hostapd is a utility that creates a WiFi access point. Copy the hostapd configuration file:


```bash
sudo cp hostapd/fptn-hostapd.conf /etc/
```
Copy the hostapd service file:

```bash
sudo cp hostapd/fptn-hostapd.service /etc/systemd/system/
```

Open the file /etc/fptn-hostapd.conf and replace the values with your own:

```bash
# Replace with your WiFi interface
interface=wlan0

# Replace with your WiFi network name
ssid=VPN-FPTN

# Replace with your WiFi password
wpa_passphrase=1passwordpassword
```

#### Step 5: Configure Dnsmasq

Dnsmasq is a tool that automatically assigns IP addresses to all clients connected to the WiFi. Copy the dnsmasq configuration file:

```bash
sudo cp hostapd/fptn-dnsmasq.conf /etc/
```

Copy the dnsmasq service file:


```bash
sudo cp hostapd/fptn-dnsmasq.service /etc/systemd/system/
```

### Step 6: Traffic Routing Setup

To route packets from the WiFi interface through the VPN, perform the following steps:
Copy the network setup service file:


```bash
sudo cp fptn-setup-network/fptn-setup-network.service /etc/systemd/system/
```

Copy the network setup script:

```bash
sudo cp fptn-setup-network/fptn-setup-network.sh /usr/sbin/
```

Откройте файл `/usr/sbin/fptn-setup-network.sh` и замените данные на ваши:

```bash
# Replace with your WiFi interface
WIFI_INTERFACE=wlan0

# Replace with your Ethernet interface
ETH_INTERFACE=eth0
```

### Step 7: Restart and Enable Services

Reload the systemd daemon:

```bash
sudo systemctl daemon-reload
```

Enable and restart the hostapd service:

```bash
sudo systemctl enable fptn-hostapd.service
sudo systemctl restart fptn-hostapd.service
```

Enable and restart the dnsmasq service:

```bash
sudo systemctl enable fptn-dnsmasq.service
sudo systemctl restart fptn-dnsmasq.service
```

Enable and start the network setup service:

```bash
sudo systemctl enable fptn-setup-network.service
sudo systemctl start fptn-setup-network.service
```

After completing these steps, your Raspberry Pi will be configured as a WiFi access point with VPN functionality.
