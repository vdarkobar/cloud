#!/usr/bin/env bash
# remove-old-kernels.sh - Interactive & non-interactive script to purge old Proxmox kernels

set -euo pipefail

# Default backup locations
BACKUP_DIR="/root/kernel-backup"
GRUB_BACKUP="${BACKUP_DIR}/grub.cfg.backup"

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
  echo "Error: This script must be run as root (use sudo)." >&2
  exit 1
fi

# Verify Proxmox environment
if ! command -v pveversion >/dev/null 2>&1 || [[ ! -d /etc/pve ]]; then
  echo "Error: This script is designed for Proxmox VE systems only." >&2
  exit 1
fi

# Check dependencies
for cmd in dpkg apt-get update-grub; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Error: Required command '$cmd' not found." >&2
    exit 1
  fi
done

# Default settings
DRY_RUN=false
yes_flag=false
AUTO_REMOVE=false
LOGFILE=""
LANGUAGE="en"
QUIET=false
MIN_KERNELS=1  # Minimum number of kernels to keep (besides current)
BACKUP=true    # Enable backup by default

# Localization strings
declare -A MSG
MSG[en_help]=$"Usage: $0 [options]\n\nOptions:\n  -h, --help         Show this help message and exit\n  -n, --dry-run      Show what would be removed without executing\n  -a, --auto         Non-interactive: remove all old kernels\n  -y, --yes          Assume 'yes' to prompts\n  -q, --quiet        Suppress non-error output\n  -l, --log FILE     Append output to LOGFILE\n  -m, --min NUM      Keep at least NUM kernels besides current (default: 1)\n  --no-backup        Disable GRUB configuration backup\n"
MSG[en_no_old]=$"No old kernels detected. Current kernel: %s\n"
MSG[en_available]=$"Available kernels for removal:\n"
MSG[en_select]=$"Select kernels to remove (e.g., 1,3-5 or all): "
MSG[en_invalid_sel]=$"No valid selection made. Exiting.\n"
MSG[en_confirm]=$"Proceed with removal? (y/n): "
MSG[en_aborted]=$"Aborted.\n"
MSG[en_removing]=$"Removing %s...\n"
MSG[en_removed]=$"Successfully removed: %s\n"
MSG[en_fail]=$"Failed to remove: %s\n"
MSG[en_cleanup]=$"Cleaning up...\n"
MSG[en_done]=$"Cleanup and GRUB update complete.\n"
MSG[en_backup_created]=$"Backup created at %s\n"
MSG[en_keep_min]=$"Error: Selection would remove too many kernels. Keeping at least %d kernel(s) besides current.\n"
MSG[en_restore_info]=$"If boot fails, you can restore GRUB config using:\n  # boot from recovery and mount your system, then:\n  cp %s /path/to/mounted/boot/grub/grub.cfg\n"

# German translations (extend as needed)
MSG[de_help]=$"Verwendung: $0 [Optionen]\n\nOptionen:\n  -h, --help         Hilfe anzeigen und beenden\n  -n, --dry-run      Zeigt, was entfernt würde, ohne auszuführen\n  -a, --auto         Nicht-interaktiv: Entfernt alle alten Kernel\n  -y, --yes          ‚Ja' zu allen Eingabeaufforderungen annehmen\n  -q, --quiet        Unterdrückt nicht-fehlerhafte Ausgaben\n  -l, --log DATEI    Protokoll anhängen an DATEI\n  -m, --min NUM      Mindestens NUM Kernel neben dem aktuellen behalten (Standard: 1)\n  --no-backup        Deaktiviert die Sicherung der GRUB-Konfiguration\n"
MSG[de_no_old]=$"Keine alten Kernel gefunden. Aktueller Kernel: %s\n"
MSG[de_available]=$"Verfügbare Kernel zum Entfernen:\n"
MSG[de_select]=$"Kernel zum Entfernen auswählen (z.B. 1,3-5 oder all): "
MSG[de_invalid_sel]=$"Keine gültige Auswahl getroffen. Beendet.\n"
MSG[de_confirm]=$"Entfernung durchführen? (j/n): "
MSG[de_aborted]=$"Abgebrochen.\n"
MSG[de_removing]=$"Entferne %s...\n"
MSG[de_removed]=$"Erfolgreich entfernt: %s\n"
MSG[de_fail]=$"Entfernen fehlgeschlagen: %s\n"
MSG[de_cleanup]=$"Aufräumen...\n"
MSG[de_done]=$"Aufräumen und GRUB-Aktualisierung abgeschlossen.\n"
MSG[de_backup_created]=$"Sicherung erstellt unter %s\n"
MSG[de_keep_min]=$"Fehler: Auswahl würde zu viele Kernel entfernen. Behalte mindestens %d Kernel neben dem aktuellen.\n"
MSG[de_restore_info]=$"Bei Boot-Fehlern können Sie die GRUB-Konfiguration wiederherstellen mit:\n  # Starten Sie von einem Recovery-System und mounten Sie Ihr System, dann:\n  cp %s /pfad/zum/gemounteten/boot/grub/grub.cfg\n"

# Parse LANG
if [[ ${LANG:-} =~ ^de ]]; then
  LANGUAGE="de"
fi

# Helper to get localized message
# Prints localized message with proper format specifiers, respecting QUIET mode
echo_msg() {
  local key="$LANGUAGE"_$1
  if [[ -n "${MSG[$key]:-}" && ( "$QUIET" != true || "$1" =~ ^(fail|invalid_sel|aborted|keep_min)$ ) ]]; then
    printf "${MSG[$key]}" "${@:2}"
  fi
}

# Usage function
usage() {
  echo_msg help
  exit 0
}

# Backup GRUB configuration
backup_grub() {
  if [[ "$BACKUP" == true ]]; then
    mkdir -p "$BACKUP_DIR" || { echo "Error: Cannot create backup directory $BACKUP_DIR." >&2; return 1; }
    
    # Add timestamp to backup
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local backup_file="${GRUB_BACKUP}_${timestamp}"
    
    if [[ -f /boot/grub/grub.cfg ]]; then
      cp -f /boot/grub/grub.cfg "$backup_file" || { echo "Error: Failed to backup GRUB config." >&2; return 1; }
      echo_msg backup_created "$backup_file"
      echo_msg restore_info "$backup_file"
      return 0
    else
      echo "Error: GRUB configuration not found at /boot/grub/grub.cfg" >&2
      return 1
    fi
  fi
  return 0
}

# Parse CLI options
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage ;;
    -n|--dry-run) DRY_RUN=true; shift ;;
    -a|--auto) AUTO_REMOVE=true; shift ;;
    -y|--yes) yes_flag=true; shift ;;
    -q|--quiet) QUIET=true; shift ;;
    -m|--min)
      if [[ -z "${2:-}" || ! "${2:-}" =~ ^[0-9]+$ ]]; then
        echo "Error: --min requires a numeric value." >&2
        exit 1
      fi
      MIN_KERNELS="$2"
      shift 2
      ;;
    --no-backup) BACKUP=false; shift ;;
    -l|--log)
      if [[ -z "${2:-}" ]]; then
        echo "Error: --log requires a file path." >&2
        exit 1
      fi
      LOGFILE="$2"
      shift 2
      ;;
    *) printf "Error: Unknown option: %s\n" "$1" >&2; usage ;;
  esac
done

# Setup logging
if [[ -n "$LOGFILE" ]]; then
  log_dir=$(dirname "$LOGFILE")
  if [[ ! -d "$log_dir" ]]; then
    mkdir -p "$log_dir" || { echo "Error: Cannot create log directory $log_dir." >&2; exit 1; }
  fi
  if [[ -e "$LOGFILE" && ! -w "$LOGFILE" ]] || ! touch "$LOGFILE" 2>/dev/null; then
    echo "Error: Log file $LOGFILE is not writable." >&2
    exit 1
  fi
  exec > >(tee -a "$LOGFILE") 2>&1
fi

# Detect current kernel
current_kernel=$(uname -r)
# List all installed PVE kernels except running one
mapfile -t AVAILABLE_KERNELS < <(dpkg --list 2>/dev/null \
  | awk '/^ii[[:space:]]+pve-kernel-[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-pve/ {print $2}' \
  | grep -v -- "$current_kernel" \
  | sort -V) || { echo "Error: Failed to list kernels." >&2; exit 1; }

# Early exit if no old kernels found
if [[ ${#AVAILABLE_KERNELS[@]} -eq 0 ]]; then
  echo_msg no_old "$current_kernel"
  exit 0
fi

# Display available kernels
echo_msg available
for i in "${!AVAILABLE_KERNELS[@]}"; do
  printf "%2d. %s\n" $((i+1)) "${AVAILABLE_KERNELS[i]}"
done

# Handle minimum kernel requirement
if [[ ${#AVAILABLE_KERNELS[@]} -le $MIN_KERNELS ]]; then
  echo_msg keep_min "$MIN_KERNELS"
  exit 1
fi

# Determine kernel selection
if $AUTO_REMOVE; then
  # In auto mode, keep the minimum number of most recent kernels
  if [[ $MIN_KERNELS -gt 0 ]]; then
    selection=$(seq 1 $((${#AVAILABLE_KERNELS[@]} - MIN_KERNELS)) | tr '\n' ',' | sed 's/,$//')
  else
    selection="all"
  fi
else
  read -rp "$(echo_msg select)" selection
fi

# Build removal list using a more robust approach
kernels_to_remove=()

# Safer selection parsing
parse_selection() {
  local sel="$1"
  local -A selected_indices=()  # Using associative array to track selections
  
  if [[ "$sel" == "all" ]]; then
    # Keep minimum kernels from the end (newest)
    local to_keep=$MIN_KERNELS
    local to_remove=$((${#AVAILABLE_KERNELS[@]} - to_keep))
    
    if [[ $to_remove -le 0 ]]; then
      return  # Nothing to remove
    fi
    
    for ((i=0; i<to_remove; i++)); do
      kernels_to_remove+=("${AVAILABLE_KERNELS[i]}")
    done
    return
  fi
  
  # Clean input and convert to array of parts
  sel=$(echo "$sel" | tr -d '[:space:]')
  IFS=',' read -ra parts <<<"$sel"
  
  for part in "${parts[@]}"; do
    if [[ "$part" =~ ^([0-9]+)-([0-9]+)$ ]]; then
      local start="${BASH_REMATCH[1]}"
      local end="${BASH_REMATCH[2]}"
      
      # Validate range
      if [[ $start -lt 1 || $end -lt 1 || 
            $start -gt ${#AVAILABLE_KERNELS[@]} || 
            $end -gt ${#AVAILABLE_KERNELS[@]} ]]; then
        continue  # Skip invalid range
      fi
      
      # Process range
      for ((idx=start; idx<=end; idx++)); do
        selected_indices[$idx]=1
      done
    elif [[ "$part" =~ ^[0-9]+$ ]]; then
      local idx="$part"
      if [[ $idx -ge 1 && $idx -le ${#AVAILABLE_KERNELS[@]} ]]; then
        selected_indices[$idx]=1
      fi
    fi
  done
  
  # Build removal list from selected indices
  for idx in "${!selected_indices[@]}"; do
    kernels_to_remove+=("${AVAILABLE_KERNELS[idx-1]}")
  done
}

parse_selection "$selection"

# Sort kernels for predictable removal order
IFS=$'\n' kernels_to_remove=($(sort -V <<<"${kernels_to_remove[*]}"))
unset IFS

# Verify we're not removing too many kernels
remaining=$((${#AVAILABLE_KERNELS[@]} - ${#kernels_to_remove[@]}))
if [[ $remaining -lt $MIN_KERNELS ]]; then
  echo_msg keep_min "$MIN_KERNELS"
  exit 1
fi

# Validate selection
if [[ ${#kernels_to_remove[@]} -eq 0 ]]; then
  echo_msg invalid_sel
  exit 1
fi

# Confirm removal (unless auto or yes flag is set)
if ! $AUTO_REMOVE && ! $yes_flag; then
  printf "%s\n" "${kernels_to_remove[@]}"
  read -rp "$(echo_msg confirm)" confirm
  if [[ ! "$confirm" =~ ^[yYjJ]$ ]]; then
    echo_msg aborted
    exit 1
  fi
fi

# Backup GRUB configuration before making changes
if ! $DRY_RUN; then
  backup_grub || { echo "Failed to create backup, proceeding without backup."; }
fi

# Removal loop
echo # Blank line for readability
for kernel in "${kernels_to_remove[@]}"; do
  # Safety check: never purge running kernel
  if [[ "$kernel" == *"${current_kernel}"* ]]; then
    echo "Safety check: Skipping current kernel $kernel"
    continue
  fi

  echo_msg removing "$kernel"
  if $DRY_RUN; then
    echo "[DRY RUN] apt-get purge -y $kernel"
  else
    if ! apt-get purge -y "$kernel" >/dev/null 2>&1; then
      echo_msg fail "$kernel"
      exit 1
    else
      echo_msg removed "$kernel"
    fi
  fi
done

# Cleanup and GRUB update
if ! $DRY_RUN; then
  echo_msg cleanup
  if ! apt-get autoremove -y >/dev/null 2>&1; then
    echo "Error: apt-get autoremove failed." >&2
    exit 1
  fi
  if ! update-grub >/dev/null 2>&1; then
    echo "Error: update-grub failed." >&2
    exit 1
  fi
  echo_msg done

  # Final verification - make sure we still have kernels
  total_kernels=$(dpkg --list 2>/dev/null | grep -c '^ii[[:space:]]\+pve-kernel-' || echo "0")
  if [[ $total_kernels -lt 1 ]]; then
    echo "WARNING: No kernels detected after cleanup! System may not boot properly."
    echo "Restore from backup at $GRUB_BACKUP if needed."
  fi
fi
