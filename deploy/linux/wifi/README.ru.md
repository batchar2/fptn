
### Настройка WiFi-VPN точки доступа на Raspberry Pi

В этом руководстве описан процесс настройки точки доступа WiFi на Raspberry Pi или другом компьютере с функцией пропусканием всего трафика через VPN. Следуйте инструкциям, чтобы ваш Raspberry Pi стал полноценной точкой доступа.

#### Шаг 1: Скачайте клиентскую версию VPN клиента для ARM

Выполните настройку VPN клиента в соответсвии с этим [пунктом](https://github.com/batchar2/fptn?tab=readme-ov-file#fptn-client-installation-and-configuration)

#### Шаг 2: Установите необходимые пакеты

Для настройки точки доступа вам потребуются следующие пакеты:

```bash
sudo apt install hostapd dnsmasq
```

#### Шаг 3: Настройки системы

Отключите и остановите службы hostapd и dnsmasq, чтобы избежать конфликтов:

```bash
sudo systemctl stop hostapd
sudo systemctl disable hostapd
sudo systemctl stop dnsmasq
sudo systemctl disable dnsmasq
```

#### Шаг 4: Дополнительные настройки для systemd

Если вы используете Ubuntu 24.04/22.04, выполните следующие дополнительные шаги:

Откройте файл `/etc/systemd/resolved.conf`


Найдите параметр DNSStubListener, раскомментируйте его и измените значение на no:

```bash
DNSStubListener=no
``` 

Перезапустите службу systemd-resolved:

```bash
sudo systemctl restart systemd-resolved
```

Перезагрузите систему:

```bash
sudo reboot
```


#### Шаг 5: Настройка Hostapd

Hostapd утилита которая создаст wifi-точку доступа. Скопируйте файл конфигурации hostapd:

```bash
sudo cp hostapd/fptn-hostapd.conf /etc/
```
Скопируйте файл службы hostapd:

```bash
sudo cp hostapd/fptn-hostapd.service /etc/systemd/system/
```

Откройте файл /etc/fptn-hostapd.conf и замените значения на ваши:

```bash
#  Замените на ваш интерфейс WiFi
interface=wlan0

#  Замените на имя вашей WiFi сети
ssid=VPN-FPTN

#  Замените на ваш пароль
wpa_passphrase=1passwordpassword
```

#### Шаг 6: Настройка dnsmasq

Dnsmasq инструмент, который всем клиентам подключенным к WiFi будет автоматически выдавать IP адреса.

Скопируйте файл конфигурации dnsmasq:

```bash
sudo cp hostapd/fptn-dnsmasq.conf /etc/
```

Скопируйте файл службы dnsmasq:

```bash
sudo cp hostapd/fptn-dnsmasq.service /etc/systemd/system/
```

### Шаг 7: Настройка маршрутизации трафика

Для того, чтобы пакеты с wifi-интерфейса попадали в VPN нужно сделать маршрутизацию трафика

Скопируйте файл службы для настройки сети:

```bash
sudo cp fptn-setup-network/fptn-setup-network.service /etc/systemd/system/
```

Скопируйте скрипт настройки сети:
```bash
sudo cp fptn-setup-network/fptn-setup-network.sh /usr/sbin/
```

Откройте файл `/usr/sbin/fptn-setup-network.sh` и замените данные на ваши:

```bash
#  Замените на ваш WiFi интерфейс
WIFI_INTERFACE=wlan0

#  Замените на ваш Ethernet интерфейс
ETH_INTERFACE=eth0
```

### Шаг 7: Перезапустите и включите службы

Перезагрузите демон systemd:

```bash
sudo systemctl daemon-reload
```

Включите и перезапустите службу hostapd:
```bash
sudo systemctl enable fptn-hostapd.service
sudo systemctl restart fptn-hostapd.service
```

Включите и перезапустите службу dnsmasq:

```bash
sudo systemctl enable fptn-dnsmasq.service
sudo systemctl restart fptn-dnsmasq.service
```

Включите и запустите службу настройки сети:

```bash
sudo systemctl enable fptn-setup-network.service
sudo systemctl start fptn-setup-network.service
```

После выполнения этих шагов ваш Raspberry Pi будет настроен как точка доступа WiFi с функцией VPN.