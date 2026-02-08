#!/bin/bash
# Linux SystemScan - Manual scan trigger
# Usage: ./scan.sh
#
# Cronjob example (every 15 minutes):
# */15 * * * * /opt/linux_systemscan/scan.sh >> /opt/linux_systemscan/scanner/cron.log 2>&1

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
"${SCRIPT_DIR}/scanner/venv/bin/python" "${SCRIPT_DIR}/scanner/scan.py"
