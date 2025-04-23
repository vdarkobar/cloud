#!/usr/bin/env bash
set -euo pipefail

# Enhanced non-interactive updater for Proxmox VE LXC containers
# Inlined logic: no functions
# Processes containers sequentially, one at a time

# Prefix for snapshots (configurable via environment variable)
snap_prefix=${SNAP_PREFIX:-"pre-update"}
# Temporary file to record containers needing reboot
reboot_file=$(mktemp)
# Ensure temporary file is cleaned up on exit
trap 'rm -f "$reboot_file"' EXIT
# Flag to stop processing new containers on signal
stop=false

# Trap SIGINT/SIGTERM to allow graceful shutdown
trap 'stop=true; echo -e "\n[WARN] Signal received; no new updates will start."' SIGINT SIGTERM

# Retrieve all container IDs (skip header)
containers=( $(pct list | awk 'NR>1{print $1}') )

# Iterate over each container
for ct in "${containers[@]}"; do
  # Break if stop flag is set
  $stop && break

  # Process each container sequentially
  # Skip template containers
  if pct config "$ct" 2>/dev/null | grep -qE '^template:\s*1$'; then
    echo -e "\n[INFO] Skipping template CT $ct"
    continue
  fi

  # Capture and log initial status
  initial_status=$(pct status "$ct" | awk '{print $2}')
  echo -e "\n[INFO] CT $ct initial status: ${initial_status}"
  started=false
  if [ "$initial_status" = "stopped" ]; then
    echo -e "\n[INFO] Starting CT $ct"
    if ! pct start "$ct"; then
      echo -e "\n[ERROR] Failed to start CT $ct. Skipping."
      continue
    fi
    # Wait up to 30 seconds for container to start
    for i in {1..30}; do
      if [ "$(pct status "$ct" | awk '{print $2}')" = "running" ]; then
        break
      fi
      sleep 1
    done
    if [ "$(pct status "$ct" | awk '{print $2}')" != "running" ]; then
      echo -e "\n[ERROR] CT $ct did not start within 30 seconds. Skipping."
      continue
    fi
    started=true
  fi

  # Health check: root filesystem usage
  root_usage=$(pct exec "$ct" -- df / --output=pcent | tail -1 | tr -dc '0-9')
  if [ "$root_usage" -ge 90 ]; then
    echo -e "\n[SKIP] CT $ct: root usage ${root_usage}% >= 90%"
    $started && pct shutdown "$ct"
    continue
  fi

  # Health check: /boot usage
  boot_usage=$(pct exec "$ct" -- df /boot --output=pcent 2>/dev/null | tail -1 | tr -dc '0-9' || echo 0)
  if [ "$boot_usage" -ge 90 ]; then
    echo -e "\n[SKIP] CT $ct: /boot usage ${boot_usage}% >= 90%"
    $started && pct shutdown "$ct"
    continue
  fi

  # Health check: free memory
  mem_free=$(pct exec "$ct" -- free -m | awk '/^Mem:/ {print $4}')
  if [ "$mem_free" -lt 100 ]; then
    echo -e "\n[SKIP] CT $ct: free memory ${mem_free}MB < 100MB"
    $started && pct shutdown "$ct"
    continue
  fi

  # Create snapshot before update
  snap_name="${snap_prefix}-$(date +%Y%m%d%H%M%S)"
  echo -e "\n[INFO] Creating snapshot '$snap_name' for CT $ct"
  if ! pct snapshot "$ct" "$snap_name"; then
    echo -e "\n[ERROR] Failed to create snapshot for CT $ct. Skipping update."
    $started && pct shutdown "$ct"
    continue
  fi

  # Detect OS and log update intent
  os=$(pct config "$ct" | awk '/^ostype/ {print $2}')
  echo -e "\n[INFO] Updating CT $ct (OS=${os}), initial status=${initial_status}"
  echo

  # Inline retry logic: up to 3 attempts
  attempts=0
  success=false
  until [ "$attempts" -ge 3 ]; do
    attempts=$((attempts+1))
    case "$os" in
      alpine)
        pct exec "$ct" -- sh -c 'apk update && apk upgrade --available' && success=true
        ;;
      archlinux)
        pct exec "$ct" -- sh -c 'pacman -Syyu --noconfirm' && success=true
        ;;
      fedora|centos|rocky|alma)
        pct exec "$ct" -- sh -c 'dnf -y upgrade' && success=true
        ;;
      ubuntu|debian|devuan)
        pct exec "$ct" -- sh -c 'apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y dist-upgrade' && success=true
        ;;
      opensuse)
        pct exec "$ct" -- sh -c 'zypper refresh && zypper --non-interactive dup' && success=true
        ;;
      *)
        echo -e "\n[SKIP] CT $ct: unsupported OS '${os}'"
        break
        ;;
    esac
    if [ "$success" = true ]; then
      break
    fi
    echo -e "\n[WARN] Attempt ${attempts}/3 for CT $ct failed. Retrying in 5s..."
    sleep 5
  done

  # Final retry failure handling
  if [ "$success" = false ]; then
    echo -e "\n[ERROR] Updates for CT $ct failed after 3 attempts. Skipping."
  fi

  # Record reboot requirement
  if pct exec "$ct" -- test -f /var/run/reboot-required; then
    echo -e "\n[RESULT] CT $ct requires reboot" >> "$reboot_file"
  fi

  # Shutdown container if it was started by us
  if [ "$started" = true ]; then
    echo -e "\n[INFO] Shutting down CT $ct"
    pct shutdown "$ct"
  fi
done

# Print summary of containers needing reboot
if [ -s "$reboot_file" ]; then
  echo -e "\n[RESULT] Containers requiring reboot:" 
  sort -u "$reboot_file"
else
  echo -e "\n[RESULT] No reboots needed."
fi
