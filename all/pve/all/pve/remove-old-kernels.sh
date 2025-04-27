#!/usr/bin/env bash
# Improved script to safely remove old Proxmox kernels

set -euo pipefail

# Configuration
BACKUP_DIR="/root/kernel-backup"
MIN_KERNELS=2
DRY_RUN=false
QUIET=false

# Check root privileges
if [[ $EUID -ne 0 ]]; then
  echo "Error: Please run as root (use sudo)." >&2
  exit 1
fi

# Verify Proxmox environment
if ! command -v pveversion &>/dev/null || [[ ! -d /etc/pve ]]; then
  echo "Error: This script is intended for Proxmox VE systems only." >&2
  exit 1
fi

# Verify dependencies
for cmd in dpkg apt-get update-grub; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "Error: Required command '$cmd' is missing." >&2
    exit 1
  fi
done

# Helper function for messaging
log() {
  [[ "$QUIET" == false ]] && echo -e "$1"
}

# Backup GRUB configuration
backup_grub() {
  mkdir -p "$BACKUP_DIR"
  local backup_file="$BACKUP_DIR/grub.cfg.$(date '+%Y%m%d_%H%M%S')"

  if [[ -f /boot/grub/grub.cfg ]]; then
    cp /boot/grub/grub.cfg "$backup_file"
    log "GRUB configuration backed up to $backup_file"
  else
    echo "Warning: GRUB configuration file not found." >&2
  fi
}

# List removable kernels
list_old_kernels() {
  local current_kernel
  current_kernel=$(uname -r)

  dpkg -l 'pve-kernel-*' | awk '/^ii/{print $2}' | grep -v "$current_kernel" | sort -V
}

# Prompt for user confirmation
confirm_removal() {
  read -rp "Proceed with kernel removal? (y/N): " response
  [[ "$response" =~ ^[Yy]$ ]]
}

# Remove specified kernels
remove_kernels() {
  local kernels=("$@")

  if $DRY_RUN; then
    log "[DRY RUN] Would remove kernels: ${kernels[*]}"
  else
    apt-get purge -y "${kernels[@]}"
    apt-get autoremove -y
    update-grub
    log "Kernel removal completed. Please reboot to verify."
  fi
}

# Main execution logic
main() {
  backup_grub

  mapfile -t old_kernels < <(list_old_kernels)

  if (( ${#old_kernels[@]} <= MIN_KERNELS )); then
    log "Not enough kernels to remove. Minimum kernels retained: $MIN_KERNELS"
    exit 0
  fi

  kernels_to_remove=("${old_kernels[@]:0:${#old_kernels[@]}-MIN_KERNELS}")

  log "Kernels selected for removal:"
  for kernel in "${kernels_to_remove[@]}"; do
    log "  - $kernel"
  done

  confirm_removal || { log "Operation aborted."; exit 1; }

  remove_kernels "${kernels_to_remove[@]}"
}

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--dry-run) DRY_RUN=true; shift ;;
    -q|--quiet) QUIET=true; shift ;;
    -m|--min-kernels)
      MIN_KERNELS="$2"; shift 2;;
    -h|--help)
      echo "Usage: $0 [-n|--dry-run] [-q|--quiet] [-m|--min-kernels NUM]"; exit 0;;
    *)
      echo "Unknown option: $1"; exit 1;;
  esac
done

# Run the main function
main
