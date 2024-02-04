# Homey Watchdog

Python script to monitor a Homey Pro http port response.

If the Homey Pro doesn't respond with a proper json message, the script will reset the Unifi switch port PoE power using Unifi Network Controller API.

## Prerequisities

No changes need on your Homey Pro.

Local account is needed as super admin on the Unifi Controller.

## Usage

```text
usage: poe_switch.py [-c CONFIG]

Change the PoE Mode of UniFi switches controlled by Unifi Network Controller.

options:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Use CONFIG file for the configuration
```

## Configuration and installation

Copy `sample/homey-watchdog.conf` to the source directory and edit it for your environment.

```text
[Settings]
monitor_url = https://example.com
monitor_json_vars = var1,var2,var3
monitor_interval = 60
retry_count = 3
controller = your_controller_address
username = your_username
password = your_password
mac = your_device_mac
ports = 1,2,3
state = auto
log_level = info
test = false
```

After editing, run `make install` to install the script and configuration to `/usr/local/(bin|etc)` and the systemd service unit file to `/etc/systemd/system/`.

Now you can enable, start and stop the servive:

```text
systemctl enable homey-watchdog.service
systemctl start homey-watchdog.service
systemctl stop homey-watchdog.service
```

## Tested on

* Homey Pro 2023, firmware 10.2.1
* UniFi OS 3.2.9
* Unifi Network 8.0.28

## References

Thanks for all the hardwork at:

* [Ubiquity Community Wiki - partial API description](https://ubntwiki.com/products/software/unifi-controller/api)
* [Previous work in the Home Assistant community](https://community.home-assistant.io/t/unifi-allow-poe-switching-of-connected-unifi-devices/230358)
* [Art of WiFi - UniFi API Client (in PHP)](https://github.com/Art-of-WiFi/UniFi-API-client)
* [Python code adapted from ubios-poe_switch](https://github.com/alxwolf/ubios-poe_switch)
