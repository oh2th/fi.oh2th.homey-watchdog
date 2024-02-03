# Homey Watchdog

Python script to monitor a Homey Pro http port response.

If the Homey Pro doesn't respond with a proper json message, restarts the Unifi switch port POE power using Unifi Network Controller API.

## Usage

```
usage: poe_switch.py [-h] [-u MONITOR_URL] [-i MONITOR_INTERVAL] [-j MONITOR_JSON_VARS] [-c TRY_COUNT] [-v] [-t] controller username password mac ports state

Change the PoE Mode of UniFi switches controlled by Unifi Network Controller.

positional arguments:
  controller            hostname or IP address of UniFi Controller
  username              username with admin rights on UniFi Controller
  password              corresponding password for admin user
  mac                   MAC address (with or without colons) of switch
  ports                 comma-separated list if port numbers to set new state
  state                 desired state of PoE ports, e.g., 'auto' or 'off'

options:
  -h, --help            show this help message and exit
  -u MONITOR_URL, --monitor_url MONITOR_URL
                        URL to monitor for success, use with --monitor_json_vars
  -j MONITOR_JSON_VARS, --monitor_json_vars MONITOR_JSON_VARS
                        comma-separated list of expected variables in JSON response
  -i MONITOR_INTERVAL, --monitor_interval MONITOR_INTERVAL
                        Interval in seconds to monitor the URL (default: 60)
  -c TRY_COUNT, --try_count TRY_COUNT
                        Number of consecutive failures before triggering error actions (default: 3)
  -v, --verbose         increase output verbosity
  -t, --test            enable test mode (do not perform error actions)
```

`python3 poe_switch.py udm.example.org IamAdmin P4ssword fcec12345678 6,7 auto` will turn on the PoE (in mode `auto`) for ports 6 and 7 of the UniFi PoE switch with MAC address fc:ec:12:34:56:78.

`python3 poe_switch.py -u http://homey.example.org/ -j homeyId,homeyVersion udm.example.org IamAdmin P4ssword fcec12345678 6,7 auto` will poll target homey.example for a json message to containd both homeyId and homeyVersion variables. If for any reason the request fails, it will connect to the Unifi Controller at udm.example.org and tell it first to turn OFF the ports and then back to requested state on Unifi PoE switch with MAC address.

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
