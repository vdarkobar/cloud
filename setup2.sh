#!/bin/bash

clear

#############################################################################
# Define ANSI escape sequences for colored fonts (green, red, yellow, etc.) #
#############################################################################

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

#################
# Intro message #
#################

echo
echo -e "${GREEN} Proxmox VE:${NC}"
sleep 1
echo -e "${GREEN} The script generates a new Debian LXC Template and sets up a non-root user to improve security.${NC}"
echo

#############################################################
# Gathering storage information for the Debian LXC Template #
#############################################################

template_storage_list=$(pvesm status -content vztmpl | awk 'NR>1 {print NR-1 " " $1}')
if [ -z "$template_storage_list" ]; then
    echo -e "${RED} No storage found or failed to retrieve storage status.${NC}"
    exit 1
fi

echo
echo -e "${WHITE}[INFO] ${YELLOW}Available Template Storage:${WHITE}"
echo "$template_storage_list"
default_template_storage=$(echo "$template_storage_list" | awk 'NR==1 {print $2}')
while true; do
    echo -ne "${GREEN}Select the template storage [default: $default_template_storage]: ${WHITE}"
    read -r template_storage_number
    template_storage_number=${template_storage_number:-1}
    template_storage=$(echo "$template_storage_list" | awk -v num="$template_storage_number" '$1 == num {print $2}')
    if [ -z "$template_storage" ]; then
        echo -e "${WHITE}[ERROR] ${RED}Invalid selection, please try again.${WHITE}"
    else
        echo -e "${WHITE}[INFO] ${GREEN}Selected Template Storage:${WHITE} $template_storage"
        break
    fi
done

# Get storage information for rootfs
rootfs_storage_list=$(pvesm status -content rootdir | awk 'NR>1 {print NR-1 " " $1}')
if [ -z "$rootfs_storage_list" ]; then
    echo -e "${RED} No storage found or failed to retrieve storage status.${NC}"
    exit 1
fi

echo
echo -e "${WHITE}[INFO] ${YELLOW}Available rootfs Storage:${WHITE}"
echo "$rootfs_storage_list"
default_rootfs_storage=$(echo "$rootfs_storage_list" | awk 'NR==1 {print $2}')
while true; do
    echo -ne "${GREEN}Select the rootfs storage [default: $default_rootfs_storage]: ${WHITE}"
    read -r rootfs_storage_number
    rootfs_storage_number=${rootfs_storage_number:-1}
    rootfs_storage=$(echo "$rootfs_storage_list" | awk -v num="$rootfs_storage_number" '$1 == num {print $2}')
    if [ -z "$rootfs_storage" ]; then
        echo -e "${WHITE}[ERROR] ${RED}Invalid selection, please try again.${WHITE}"
    else
        echo -e "${WHITE}[INFO] ${GREEN}Selected rootfs Storage:${WHITE} $rootfs_storage"
        break
    fi
done

############################
# Determining Container ID #
############################

NEXT_CONTAINER_ID=$(pvesh get /cluster/nextid)
if [ $? -ne 0 ] || [ -z "$NEXT_CONTAINER_ID" ]; then
    echo -e "${RED} Failed to retrieve the next available container ID.${NC}"
    exit 1
fi

echo
echo -e "${WHITE}[INFO] ${YELLOW}Next available container ID:${WHITE} $NEXT_CONTAINER_ID"
echo -ne "${GREEN}Enter Container ID [default: $NEXT_CONTAINER_ID]: ${WHITE}"
read -r CONTAINER_ID
CONTAINER_ID="${CONTAINER_ID:-$NEXT_CONTAINER_ID}"
echo -e "${WHITE}[INFO] ${GREEN}Selected Container ID:${WHITE} $CONTAINER_ID"

########################
# Determining Hostname #
########################

reserved_names=("localhost" "domain" "local" "host" "broadcasthost" "localdomain" "loopback" "wpad" "gateway" "dns" "mail" "ftp" "web")
is_reserved_name() {
    local input_name=$1
    for name in "${reserved_names[@]}"; do
        if [[ "$input_name" == "$name" ]]; then
            return 0
        fi
    done
    return 1
}
DEFAULT_HOSTNAME="deblxc"
while true; do
    echo
    echo -ne "${WHITE}[INFO] ${YELLOW}Enter hostname for the container [default: $DEFAULT_HOSTNAME]:${WHITE} "
    read -r HOSTNAME
    HOSTNAME="${HOSTNAME:-$DEFAULT_HOSTNAME}"
    if is_reserved_name "$HOSTNAME"; then
        echo -e "${WHITE}[ERROR] ${RED}Invalid hostname. Reserved name.${WHITE}"
    elif [[ "$HOSTNAME" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]]; then
        echo -e "${WHITE}[INFO] ${GREEN}Selected Hostname:${WHITE} $HOSTNAME"
        break
    else
        echo -e "${WHITE}[ERROR] ${RED}Invalid hostname format.${WHITE}"
    fi
done

#######################################
# Gathering non-root user information #
#######################################

while true; do
    echo
    echo -ne "${WHITE}[INFO] ${YELLOW}Enter username for a non-root user:${WHITE} "
    read -r username
    if [ "$username" == "root" ]; then
        echo -e "${WHITE}[ERROR] ${RED}Username 'root' is not allowed.${WHITE}"
    elif [[ "$username" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
        if id "$username" &>/dev/null; then
            echo -e "${WHITE}[ERROR] ${RED}User '$username' already exists.${WHITE}"
        else
            echo -e "${WHITE}[INFO] ${GREEN}Selected Username:${WHITE} $username"
            break
        fi
    else
        echo -e "${WHITE}[ERROR] ${RED}Invalid username. Use lowercase letters, digits, dashes, or underscores.${WHITE}"
    fi
done

while true; do
    echo
    echo -ne "${WHITE}[INFO] ${YELLOW}Enter password for user '${username}':${WHITE} "
    read -s password
    echo
    echo -ne "${WHITE}[INFO] ${YELLOW}Re-enter password for verification:${WHITE} "
    read -s password2
    echo
    if [ "$password" != "$password2" ]; then
        echo -e "${WHITE}[ERROR] ${RED}Passwords do not match. Please try again.${WHITE}"
    elif [ ${#password} -lt 8 ]; then
        echo -e "${WHITE}[ERROR] ${RED}Password must be at least 8 characters long.${WHITE}"
    elif ! [[ "$password" =~ [0-9] ]] || ! [[ "$password" =~ [^a-zA-Z0-9] ]]; then
        echo -e "${WHITE}[ERROR] ${RED}Password must contain at least one number and one special character.${WHITE}"
    else
        echo -e "${WHITE}[INFO] ${GREEN}Password set successfully.${WHITE}"
        break
    fi
done

#########################################################
# Bridge Selection: Determining Template Network Bridge #
#########################################################

echo
echo -e "${WHITE}[INFO] ${YELLOW}Available network bridges:${WHITE}"
AVAILABLE_BRIDGES=$(ip -o link show | awk -F': ' '{print $2}' | grep '^vmbr')
if [ -z "$AVAILABLE_BRIDGES" ]; then
    echo -e "${WHITE}[ERROR] ${RED}No network bridges found. Please ensure bridges are configured.${WHITE}"
    exit 1
fi

echo "$AVAILABLE_BRIDGES" | nl -s ') '
DEFAULT_BRIDGE="vmbr0"
echo -ne "${GREEN}Enter network bridge [default: $DEFAULT_BRIDGE]: ${WHITE}"
read BRIDGE_SELECTION
BRIDGE_SELECTION="${BRIDGE_SELECTION:-$DEFAULT_BRIDGE}"

if [[ "$BRIDGE_SELECTION" =~ ^[0-9]+$ ]]; then
    BRIDGE=$(echo "$AVAILABLE_BRIDGES" | sed -n "${BRIDGE_SELECTION}p")
else
    BRIDGE="$BRIDGE_SELECTION"
fi
echo -e "${WHITE}[INFO] ${GREEN}Selected network bridge:${WHITE} $BRIDGE"

###################################################################
# Obtaining the latest Debian LXC Template and creating container #
###################################################################

# Update template list
echo
if ! pveam update; then
    echo -e "${RED} Failed to update template list. Please check your network or repository configuration.${NC}"
    exit 1
fi

echo

# Retrieve the latest Debian LXC template name
latest_debian_template=$(pveam available --section system | awk '/debian/ {print $2}' | sort -V | tail -n 1)
if [ -z "$latest_debian_template" ]; then
    echo -e "${RED} No Debian templates available for download. Please check your Proxmox repository settings or network connection.${NC}"
    exit 1
fi

echo -e "${YELLOW} Downloading${NC} $latest_debian_template ${YELLOW}to${NC} $template_storage${YELLOW}...${NC}"
echo
if ! pveam download "$template_storage" "$latest_debian_template"; then
    echo -e "${RED} Failed to download the template. Please check your storage configuration and network connection, and ensure the template is still available in the repository.${NC}"
    exit 1
fi

echo
echo -e "${GREEN} Template${NC} $latest_debian_template ${GREEN}downloaded successfully to${NC} $template_storage${NC}"
echo

echo -e "${YELLOW} Searching for the Debian template in the filesystem...${NC}"
template_path=$(find / -name "$latest_debian_template" 2>/dev/null)
if [ -z "$template_path" ]; then
    echo -e "${RED} Failed to locate the template:${NC} $latest_debian_template"
    echo -e "${RED} Please check the template name and ensure it has been downloaded.${NC}"
    exit 1
fi

echo
echo -e "${GREEN} Template located at:${NC} $template_path"
echo

#########################
# Creating LXC Template #
#########################

# Creating the LXC container with the specified parameters. Note the bridge is now dynamic.
pct create $CONTAINER_ID $template_path \
    --arch amd64 \
    --ostype debian \
    --hostname $HOSTNAME \
    --unprivileged 1 \
    --features nesting=1 \
    --password $password \
    --ignore-unpack-errors \
    --ssh-public-keys /root/.ssh/authorized_keys \
    --storage $rootfs_storage \
    --rootfs $rootfs_storage:8 \
    --cores 4 \
    --memory 4096 \
    --swap 512 \
    --net0 name=eth0,bridge=$BRIDGE,firewall=1,ip=dhcp \
    --start 1

# Allow the container to initialize
sleep 5

echo
echo -e "${WHITE}[INFO] ${YELLOW}Configuring locales in the container to avoid locale warnings...${WHITE}"
echo
pct exec $CONTAINER_ID -- bash -c "
    apt-get update -y && \
    apt-get upgrade -y && \
    apt-get install -y locales && \
    sed -i 's/^# *en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && \
    locale-gen en_US.UTF-8 && \
    update-locale LANG=en_US.UTF-8
"
# Optional: Ensure locale variables are set system-wide (if desired)
pct exec $CONTAINER_ID -- bash -c "echo 'LANG=en_US.UTF-8' >> /etc/environment"
pct exec $CONTAINER_ID -- bash -c "echo 'LC_ALL=en_US.UTF-8' >> /etc/environment"
echo
echo -e "${WHITE}[INFO] ${GREEN}Locale configuration completed successfully.${WHITE}"
echo

# Add user and configure the container
pct exec $CONTAINER_ID -- bash -c "
apt-get install -y sudo cloud-init && \
adduser --gecos ',,,,' --disabled-password $username && \
usermod -aG sudo $username && \
echo '$username:$password' | chpasswd && \
passwd -l root
"

# Enable Cloud-Init services inside the container so it runs at next boot
pct exec $CONTAINER_ID -- systemctl enable cloud-init
pct exec $CONTAINER_ID -- systemctl enable cloud-config
pct exec $CONTAINER_ID -- systemctl enable cloud-final

# Provide a Cloud-Init user-data file to regenerate SSH keys
pct exec $CONTAINER_ID -- bash -c "mkdir -p /var/lib/cloud/seed/nocloud"
pct exec $CONTAINER_ID -- bash -c 'cat > /var/lib/cloud/seed/nocloud/user-data <<EOF
#cloud-config
ssh_deletekeys: true
ssh_genkeytypes: [ "rsa", "ecdsa", "ed25519" ]
EOF'
pct exec $CONTAINER_ID -- bash -c "touch /var/lib/cloud/seed/nocloud/meta-data"

# Prepare the container for template conversion
pct exec $CONTAINER_ID -- bash -c "
apt-get clean && \
rm -f /etc/ssh/ssh_host_* && \
rm -f /etc/machine-id && \
touch /etc/machine-id && \
truncate -s 0 /var/log/*log
"

############
# LXC Tags #
############

# LXC IP-Tag for running containers
# Proxmox version check
if ! pveversion | grep -Eq 'pve-manager/8\.[0-9]+'; then
  echo "[ERROR] Requires Proxmox VE 8.x or later."
  exit 1
fi

FILE_PATH="/opt/lxc-iptag/iptag"
if [[ ! -f "$FILE_PATH" ]]; then
  # install dependencies
  apt-get install -y ipcalc net-tools -qq

  # setup directories
  mkdir -p /opt/lxc-iptag

  # default config
  CONFIG_FILE="/opt/lxc-iptag/iptag.conf"
  if [[ ! -f "$CONFIG_FILE" ]]; then
    cat <<EOF > "$CONFIG_FILE"
# Configuration for LXC IP tagging

# Allowed CIDRs
CIDR_LIST=(
  192.168.0.0/16
  172.16.0.0/12
  10.0.0.0/8
)

# Timing intervals (seconds)
LOOP_INTERVAL=120           # 2 minutes - Main script loop frequency
FW_NET_INTERFACE_CHECK_INTERVAL=300  # 5 minutes - Check for firewall interface changes
LXC_STATUS_CHECK_INTERVAL=-1         # disabled
FORCE_UPDATE_INTERVAL=7200           # 120 minutes (2 hours) - Force update regardless of changes
EOF
    # echo "Default config written."
  else
    echo "Config already exists; skipping."
  fi

  # main script
  IPTAG_SCRIPT="/opt/lxc-iptag/iptag"
  cat <<'EOF' > "$IPTAG_SCRIPT"
#!/usr/bin/env bash
# LXC IP-Tag main logic

# Load configuration
source /opt/lxc-iptag/iptag.conf

# Convert dotted IP to integer
ip_to_int() {
  IFS=. read -r a b c d <<< "$1"
  echo $((a<<24 | b<<16 | c<<8 | d))
}

# Test single CIDR membership
ip_in_cidr() {
  local ip_int=$(ip_to_int "$1")
  local mask=$(ipcalc -b "$2" | awk '/Broadcast/ {print $2}')
  local net_int=$(ip_to_int "$mask")
  (( (ip_int & net_int) == ip_int ))
}

# Test any CIDR in list
ip_in_cidrs() {
  for cidr in "${CIDR_LIST[@]}"; do
    ip_in_cidr "$1" "$cidr" && return 0
  done
  return 1
}

# Validate IPv4 format
is_valid_ipv4() {
  local ip=$1
  [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r -a parts <<< "$ip"
  for part in "${parts[@]}"; do
    (( part>=0 && part<=255 )) || return 1
  done
  return 0
}

# Detect changes in LXC list
lxc_status_changed() {
  local current=$(pct list 2>/dev/null)
  [[ "$current" != "${last_lxc_status:-}" ]]
  last_lxc_status="$current"
}

# Detect changes in firewall interface list
fw_net_interface_changed() {
  local current=$(ifconfig | grep '^fw')
  [[ "$current" != "${last_net_interface:-}" ]]
  last_net_interface="$current"
}

# Update container tags to match valid IPs
update_lxc_iptags() {
  for vmid in $(pct list 2>/dev/null | awk 'NR>1 {print $1}'); do
    # collect old valid IP tags
    local old_ips=() new_tags=()
    mapfile -t tags < <(pct config "$vmid" | awk '/tags/ {print $2}' | tr ';' '\n')
    for tag in "${tags[@]}"; do
      is_valid_ipv4 "$tag" && old_ips+=("$tag") && continue
      new_tags+=("$tag")
    done

    # collect current valid IPs
    for ip in $(lxc-info -n "$vmid" -i | awk '{print $2}'); do
      if is_valid_ipv4 "$ip" && ip_in_cidrs "$ip"; then
        new_tags+=("$ip")
      fi
    done

    # skip if no change
    if [[ "$(printf '%s\n' "${old_ips[@]}" | sort -u)" == "$(printf '%s\n' "${new_tags[@]}" | sort -u)" ]]; then
      continue
    fi

    # apply new tags
    pct set "$vmid" -tags "$(IFS=';'; echo "${new_tags[*]}")"
  done
}

# Periodic checks and forced update
check() {
  local now=$(date +%s)

  if (( LXC_STATUS_CHECK_INTERVAL>0 && now - last_lxc_check >= LXC_STATUS_CHECK_INTERVAL )); then
    last_lxc_check=$now
    lxc_status_changed && update_lxc_iptags && last_update=$now
    return
  fi

  if (( FW_NET_INTERFACE_CHECK_INTERVAL>0 && now - last_net_check >= FW_NET_INTERFACE_CHECK_INTERVAL )); then
    last_net_check=$now
    fw_net_interface_changed && update_lxc_iptags && last_update=$now
    return
  fi

  if (( now - last_update >= FORCE_UPDATE_INTERVAL )); then
    update_lxc_iptags
    last_update=$now
  fi
}

main() {
  last_lxc_check=0
  last_net_check=0
  last_update=0
  while true; do
    check
    sleep "$LOOP_INTERVAL"
  done
}

main
EOF

  chmod +x "$IPTAG_SCRIPT"

  # systemd service
  SERVICE_FILE="/etc/systemd/system/iptag.service"
  cat <<EOF > "$SERVICE_FILE"
[Unit]
Description=LXC IP-Tag service
After=network.target

[Service]
Type=simple
ExecStart=$IPTAG_SCRIPT
Restart=always

[Install]
WantedBy=multi-user.target
EOF

  # enable and start
  systemctl daemon-reload
  systemctl enable --now iptag.service
else
  echo "Already installed at ${FILE_PATH}; skipping installation."
fi

# Set default Tags (comma separated for more tags)
DEBIAN_VERSION=$(pct exec $CONTAINER_ID -- cat /etc/debian_version)
TAGS="lxc;debian$DEBIAN_VERSION"
echo "tags: $TAGS" >> /etc/pve/lxc/$CONTAINER_ID.conf

# Add a description for the template
# assume $CONTAINER_ID is already set

#echo "description: <img src=\"https://github.com/vdarkobar/cloud/blob/main/misc/debian-logo.png?raw=true\" alt=\"Debian Logo\"/><br><details><summary>Click to expand</summary>some info here...</details>" \
#  >> /etc/pve/lxc/${CONTAINER_ID}.conf

cat <<'EOF' >> /etc/pve/lxc/${CONTAINER_ID}.conf
description: <img src="https://github.com/vdarkobar/cloud/blob/main/misc/debian-logo.png?raw=true" alt="Debian Logo"/><br><details><summary>Click to expand</summary>some info here...</details>
EOF

echo
echo -e " ${YELLOW}Stopping container ${WHITE}$CONTAINER_ID ($HOSTNAME) ${YELLOW}and converting it to Template...${NC}"
pct stop $CONTAINER_ID
pct template $CONTAINER_ID

if [ $? -eq 0 ]; then
    echo -e " ${GREEN}Container ${WHITE}$CONTAINER_ID ($HOSTNAME) ${GREEN}successfully converted to Template.${NC}"
    echo
    echo -e " ${GREEN}Any clones from this template will have SSH keys regenerated automatically via Cloud-Init on first boot.${NC}"
else
    echo -e "${RED}Failed to convert container $CONTAINER_ID ($HOSTNAME) to Template.${NC}"
    exit 1
fi
echo
