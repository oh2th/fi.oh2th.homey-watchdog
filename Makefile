install:
	install -m 755 homey-watchdog.py /usr/local/bin/homey-watchdog.py
	install -m 644 homey-watchdog.service /etc/systemd/system/homey-watchdog.service
	systemctl daemon-reload
	systemctl enable homey-watchdog.service
	systemctl start homey-watchdog.service

uninstall:
	systemctl stop homey-watchdog.service
	systemctl disable homey-watchdog.service
	rm -f /usr/local/bin/homey-watchdog.py
	rm -f /etc/systemd/system/homey-watchdog.service
	systemctl daemon-reload

.PHONY: install uninstall
