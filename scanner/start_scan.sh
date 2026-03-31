#!/bin/bash
# Wrapper: startet den Scanner als frank (wird von www-data via sudo aufgerufen)
cd /opt/linux_systemscan/scanner
exec /opt/linux_systemscan/scanner/venv/bin/python -u /opt/linux_systemscan/scanner/scan.py >> /opt/linux_systemscan/scanner/cron.log 2>&1
