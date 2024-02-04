#!/usr/bin/env python3

import sys
import time
import threading
import argparse
import json
import logging
import requests
from configparser import ConfigParser
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Function to read configuration from a file
def read_config(filename):
	config = ConfigParser()
	config.read(filename)
	return config

# Parse command-line arguments
parser = argparse.ArgumentParser(description='Monitor a target and reset PoE port modes on a Unifi switch.')
parser.add_argument("-c", "--config", help="Configuration file name", default='config.ini')
args = parser.parse_args()

# Read configuration from a file
config = read_config(args.config)

# Extract configuration options
settings = config['Settings']

# Get monitor URL from the configuration file
monitor_url = settings.get('monitor_url')

# Get expected variables from the configuration file
expected_vars = settings.get('monitor_json_vars', '').split(',')

# Convert monitor_interval to an integer
monitor_interval = int(settings.get('monitor_interval', 60))

# Convert retry_count to an integer
retry_count = int(settings.get('retry_count', 3))

# Unifi Controller API endpoints and login data
base_url = 'https://%s' % settings.get('controller')
login_endpoint = base_url + '/api/auth/login'
logout_endpoint = base_url + '/api/auth/logout'

login_data = {
	'username': settings.get('username'),
	'password': settings.get('password')
}

get_device_settings_endpoint = base_url + '/proxy/network/api/s/default/stat/device/%s' % settings.get('mac')
set_device_settings_endpoint = base_url + '/proxy/network/api/s/default/rest/device/'
ports_array = settings.get('ports').split(',')
desired_poe_state = settings.get('state')

if (settings.getboolean('verbose')):
	loglevel=logging.DEBUG
else:
	loglevel=logging.INFO

logging.basicConfig(level=loglevel, format='%(asctime)s - %(levelname)s - %(message)s')

s = requests.Session()

def logout(csrf_token):
	"""
	Logs out the user by sending a POST request to the logout endpoint with the provided CSRF token.

	Args:
		csrf_token (str): The CSRF token to include in the request headers.

	Returns:
		None
	"""
	logging.info("Logging out via %s.", logout_endpoint)

	logout = s.post(logout_endpoint, headers={'x-csrf-token': csrf_token}, verify=False, timeout=5)

	if logout.status_code == 200:
		logging.debug("Success.")
	else:
		logging.debug("Failed with return code %s", logout)

def login():
	"""
	Login to the specified endpoint and retrieve the CSRF token.

	Returns:
		str: The CSRF token if the login is successful.

	Raises:
		SystemExit: If the login fails with a non-200 status code.
	"""
	# working call with cURL:  Login:
	# curl -X POST --data 'username=user&password=pass' -c cookie.txt https://udm/api/auth/login
	# Get status:
	# curl -X GET -b cookie.txt https://udm/proxy/network/api/s/default/stat/device/abcdef012
	#

	logging.info("Trying to login to %s with data %s", login_endpoint, str(login_data))

	headers = {
		"Accept": "application/json",
		"Content-Type": "application/json; charset=utf-8"
	}
	login = s.post(login_endpoint, headers = headers,  json = login_data , verify = False, timeout = 5)

	if (login.status_code == 200):
		cookies = login.cookies
		logging.debug("Success. Cookies received:")
		for c in cookies:
			logging.debug("%s ==> %s", c.name, c.value)
		csrf_token = login.headers.get('X-CSRF-Token', '')  # Retrieve the CSRF token
		return csrf_token
	else:
		logging.debug("Login failed with return code %s", login.status_code)
		sys.exit()

def set_port_state(csrf_token, ports_array, desired_poe_state):
	"""
	Sets the power over Ethernet (PoE) state for the specified ports on the device.

	Args:
		csrf_token (str): The CSRF token for authentication.
		ports_array (list): The array of port indices to update.
		desired_poe_state (str): The desired PoE state to set for the ports.

	Returns:
		None
	"""
	# Get current port_overrides config for device
	global set_device_settings_endpoint  # Declare set_device_settings_endpoint as global to modify it

	logging.info ("Read current settings from %s", get_device_settings_endpoint)

	headers = {
		"Accept": "application/json",
		"Content-Type": "application/json; charset=utf-8",
	}
	r = s.get(get_device_settings_endpoint, headers = headers, verify = False, timeout = 5)

	if (r.status_code == 200):
		logging.debug("Success.")
	else:
		logging.debug("Failed with return code %s", r)
		logout(csrf_token)

	device_json = r.json()
	port_overrides = device_json['data'][0]['port_overrides']
	device_id = device_json['data'][0]['device_id']
	set_device_endpoint = set_device_settings_endpoint + device_id

	# Update the port_overrides config with new settings
	for x in ports_array:
		for value in port_overrides:
			if value['port_idx'] == int(x):
				if 'poe_mode' in value:
					if (value['poe_mode'] != desired_poe_state):
						logging.info("Updating port_idx %s from %s to %s", value['port_idx'], value['poe_mode'], desired_poe_state)
						value['poe_mode'] = desired_poe_state
					else:
						logging.info("port_idx %s already set to %s", value['port_idx'], desired_poe_state)

	# Set the updated port_overides config for device
	new_port_overrides = { 'port_overrides': port_overrides }

	logging.info("Trying to update port overrides on %s", set_device_endpoint)
	logging.debug("%s", json.dumps(new_port_overrides))

	if not settings.getboolean('test'):
		headers = {
			"Accept": "application/json",
			"Content-Type": "application/json; charset=utf-8",
			"x-csrf-token": csrf_token
		}
		update = s.put(set_device_endpoint, headers = headers, data = json.dumps(new_port_overrides), verify = False, timeout = 5)
		if (update.status_code == 200):
			logging.debug("Success.")
		else:
			logging.debug("Failed with return code %s", update.status_code)

def monitor_target_url():
	"""
	Monitor the specified URL for success and perform error actions if the URL is not successful.
	This function continuously sends HTTP requests to the specified URL and checks for a successful response.
	If the response is successful, it checks for expected JSON variables in the response.
	If any expected variable is missing or if the response is not a valid JSON, it increments the failure count.
	If the failure count exceeds the specified try count, it performs error actions and pauses monitoring for 120 seconds.
	The monitoring interval between each request is also specified.

	Args:
		None

	Returns:
		None
	"""
	consecutive_failures = 0  # Counter for tracking consecutive failures
	while True:
		try:
			logging.info("Monitoring URL: %s", monitor_url)

			# Disable certificate verification with verify=False
			response = requests.get(monitor_url, verify=False, timeout=5)

			if response.status_code == 200:
				try:
					json_data = response.json()
					# Check if specified JSON variables are present in the response
					for var in expected_vars:
						if var not in json_data:
							consecutive_failures += 1
							logging.warning("Expected variable '%s' not found in JSON response. Fail count: %s", var, consecutive_failures)
							if consecutive_failures >= retry_count:
								restart_poe_port()
								time.sleep(120)  # Pause monitoring for 120 seconds
								consecutive_failures = 0  # Reset consecutive failures counter
							break

					logging.info("Monitoring URL successful. JSON data: %s", json_data)
					consecutive_failures = 0  # Reset consecutive failures counter on successful attempt
				except json.JSONDecodeError:
					consecutive_failures += 1
					logging.warning("Monitoring URL response is not a valid JSON. Fail count: %s", consecutive_failures)
					if consecutive_failures >= retry_count:
						restart_poe_port()
						time.sleep(120)  # Pause monitoring for 120 seconds
						consecutive_failures = 0  # Reset consecutive failures counter
			else:
				consecutive_failures += 1
				logging.warning("Monitoring URL failed with status code %s. Fail count: %s", response.status_code, consecutive_failures)
				if consecutive_failures >= retry_count:
					restart_poe_port()
					time.sleep(120)  # Pause monitoring for 120 seconds
					consecutive_failures = 0  # Reset consecutive failures counter

		except Exception as e:
			consecutive_failures += 1
			logging.warning("Error while monitoring URL: %s. Fail count: %s", str(e), consecutive_failures)
			if consecutive_failures >= retry_count:
				restart_poe_port()
				time.sleep(120)  # Pause monitoring for 120 seconds
				consecutive_failures = 0  # Reset consecutive failures counter

		time.sleep(monitor_interval)

def restart_poe_port():
	"""
	Perform actions when the URL is not successful, including logging in, setting port states,
	waiting for 5 seconds, setting port states again, and logging out.

	Args:
		None

	Returns:
		None
	"""
	try:
		csrf_token = login()
		set_port_state(csrf_token, ports_array, 'off')
		time.sleep(5)
		set_port_state(csrf_token, ports_array, desired_poe_state)
		logout(csrf_token)
	except Exception as e:
		logging.warning("Error while handling error actions: %s", str(e))

"""
Start monitoring the URL if a monitor URL is specified in the configuration file.
"""
monitor_thread = threading.Thread(target=monitor_target_url)
monitor_thread.start()
