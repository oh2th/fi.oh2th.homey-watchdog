install:
	install -m 755 homey-watchdog.py /usr/local/bin/homey-watchdog.py
	install -m 644 homey-watchdog.conf /usr/local/etc/homey-watchdog.conf
	install -m 644 homey-watchdog.service /etc/systemd/system/homey-watchdog.service
	systemctl daemon-reload

uninstall:
	systemctl stop homey-watchdog.service
	systemctl disable homey-watchdog.service
	rm -f /usr/local/bin/homey-watchdog.py
	rm -f /etc/systemd/system/homey-watchdog.service
	systemctl daemon-reload

.PHONY: install uninstall
