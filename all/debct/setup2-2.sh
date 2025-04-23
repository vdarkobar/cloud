#!/usr/bin/env bash
# Uninstall script for LXC IP-Tag service and associated files
# Stops and disables the systemd service, removes unit files,
# deletes installed scripts, and cleans up logs/symlinks.

set -Eeuo pipefail
trap 'echo -e "\n[ERROR] on line $LINENO: $BASH_COMMAND"; exit 1' ERR

SERVICE_NAME="iptag.service"
UNIT_ETC="/etc/systemd/system/$SERVICE_NAME"
UNIT_LIB="/lib/systemd/system/$SERVICE_NAME"
SCRIPT_DIR="/opt/lxc-iptag"
SYMLINK="/usr/local/bin/iptag"

# 1. Stop the service if running
echo -e "\n[INFO] Stopping $SERVICE_NAME..."
if systemctl is-active --quiet "$SERVICE_NAME"; then
  systemctl stop "$SERVICE_NAME"
  echo -e "[INFO] Service stopped."
else
  echo -e "[WARN] Service was not running."
fi

# 2. Disable the service at boot
echo -e "\n[INFO] Disabling $SERVICE_NAME..."
if systemctl is-enabled --quiet "$SERVICE_NAME"; then
  systemctl disable "$SERVICE_NAME"
  echo -e "[INFO] Service disabled."
else
  echo -e "[WARN] Service was not enabled."
fi

# 3. Remove systemd unit files
echo -e "\n[INFO] Removing systemd unit files..."
if [[ -f "$UNIT_ETC" ]]; then
  rm -f "$UNIT_ETC"
  echo -e "[INFO] Removed $UNIT_ETC"
fi
if [[ -f "$UNIT_LIB" ]]; then
  rm -f "$UNIT_LIB"
  echo -e "[INFO] Removed $UNIT_LIB"
fi

# 4. Reload systemd daemons and reset failed states
echo -e "\n[INFO] Reloading systemd configuration..."
systemctl daemon-reload
systemctl reset-failed

# 5. Remove installed scripts directory
echo -e "\n[INFO] Removing IP-Tag script directory..."
if [[ -d "$SCRIPT_DIR" ]]; then
  rm -rf "$SCRIPT_DIR"
  echo -e "[INFO] Removed $SCRIPT_DIR"
else
  echo -e "[WARN] Directory $SCRIPT_DIR not found."
fi

# 6. Remove global symlink if it exists
echo -e "\n[INFO] Removing global symlink..."
if [[ -L "$SYMLINK" ]]; then
  rm -f "$SYMLINK"
  echo -e "[INFO] Removed symlink $SYMLINK"
else
  echo -e "[WARN] Symlink $SYMLINK not present."
fi

# 7. Clean up journal logs for the service
echo -e "\n[INFO] Cleaning up journal logs..."
if command -v journalctl &>/dev/null; then
  journalctl --vacuum-files=1 --unit "$SERVICE_NAME"
  echo -e "[INFO] Journal logs cleaned."
else
  echo -e "[WARN] journalctl not available; skipping log cleanup."
fi

# Final message
echo -e "\n[RESULT] LXC IP-Tag uninstallation complete.\n"
