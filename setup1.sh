#!/bin/bash

set -e

# Define color variables
YELLOW="\033[1;33m"
GREEN="\033[1;32m"
WHITE="\033[0m"
RED="\033[1;31m"  # Red for error messages

DEFAULT_IMAGE_URL="https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-nocloud-amd64.qcow2"

# Check if libguestfs-tools is installed
if ! dpkg -l | grep -q libguestfs-tools; then
   echo -e "${WHITE}[INFO] ${GREEN}libguestfs-tools is not installed. Installing it now...${WHITE}"
   apt update -qq
   apt install -y libguestfs-tools
   echo -e "${WHITE}[INFO] ${GREEN}libguestfs-tools has been installed.${WHITE}"
else
   echo -e "${WHITE}[INFO] ${GREEN}libguestfs-tools is already installed.${WHITE}"
   echo
fi

# Check for required commands
for cmd in wget qm pvesm sha512sum virt-customize; do
   if ! command -v "$cmd" >/dev/null 2>&1; then
       echo -e "${WHITE}[ERROR] ${RED}Required command '$cmd' is not installed.${WHITE}" >&2
       exit 1
   fi
done

# Get the next available VM ID
NEXT_VM_ID=$(pvesh get /cluster/nextid)
echo -e "${WHITE}[INFO] ${YELLOW}Next available VM ID:${WHITE} $NEXT_VM_ID"
echo -ne "${GREEN}Enter VM ID [default: $NEXT_VM_ID]: ${WHITE}"
read VM_ID
VM_ID="${VM_ID:-$NEXT_VM_ID}"
echo -e "${WHITE}[INFO] ${GREEN}Selected VM ID:${WHITE} $VM_ID"
echo

# Hostname validation
while true; do
   echo -ne "${GREEN}Enter hostname for the VM: ${WHITE}"
   read HOSTNAME
   if [[ $HOSTNAME =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]]; then
       echo -e "${WHITE}[INFO] ${GREEN}Selected hostname:${WHITE} $HOSTNAME"
       echo
       break
   else
       echo -e "${WHITE}[ERROR] ${RED}Invalid hostname. Use alphanumeric characters and hyphens.${WHITE}"
   fi
done

# Calculate the maximum available memory dynamically
MAX_MEMORY=$(free -m | awk '/^Mem:/{print $2}')

# Memory validation
echo -e "${WHITE}[INFO] ${YELLOW}Memory range:${WHITE} 512 MB to $MAX_MEMORY MB"
while true; do
   echo -ne "${GREEN}Enter memory size in MB [default: 4096]: ${WHITE}"
   read MEMORY
   MEMORY="${MEMORY:-4096}"
   if [[ "$MEMORY" =~ ^[0-9]+$ ]] && ((MEMORY >= 256 && MEMORY <= MAX_MEMORY)); then
       echo -e "${WHITE}[INFO] ${GREEN}Selected memory size:${WHITE} $MEMORY MB"
       echo
       break
   else
       echo -e "${WHITE}[ERROR] ${RED}Memory must be a number between 256 and $MAX_MEMORY MB.${WHITE}"
   fi
done

# Calculate the maximum number of logical cores dynamically
MAX_CORES=$(grep -c "^processor" /proc/cpuinfo)

# Cores validation
echo -e "${WHITE}[INFO] ${YELLOW}Cores range:${WHITE} 1 to $MAX_CORES"
while true; do
   echo -ne "${GREEN}Enter number of cores [default: 4]: ${WHITE}"
   read CORES
   CORES="${CORES:-4}"
   if [[ "$CORES" =~ ^[0-9]+$ ]] && ((CORES >= 1 && CORES <= MAX_CORES)); then
       echo -e "${WHITE}[INFO] ${GREEN}Selected number of cores:${WHITE} $CORES"
       echo
       break
   else
       echo -e "${WHITE}[ERROR] ${RED}Cores must be a number between 1 and $MAX_CORES.${WHITE}"
   fi
done

# List all network bridges in Proxmox
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
echo

# List available storages and select storage
echo -e "${WHITE}[INFO] ${YELLOW}Available storages for VM disks:${WHITE}"
AVAILABLE_STORAGES=$(pvesm status -content images | awk 'NR>1 && $1 ~ /^[a-zA-Z]/ {print $1}' | nl -s ') ')
echo "$AVAILABLE_STORAGES"

DEFAULT_STORAGE=$(echo "$AVAILABLE_STORAGES" | head -n 1 | awk '{print $2}') # Default to the first listed option

while true; do
    echo -ne "${GREEN}Select storage number [default: $DEFAULT_STORAGE]: ${WHITE}"
    read STORAGE_SELECTION

    # Use default if input is empty
    if [[ -z "$STORAGE_SELECTION" ]]; then
        STORAGE="$DEFAULT_STORAGE"
    elif [[ "$STORAGE_SELECTION" =~ ^[0-9]+$ ]]; then
        # Handle numeric selection and get the corresponding storage name
        STORAGE=$(echo "$AVAILABLE_STORAGES" | awk -v num="$STORAGE_SELECTION" '$1 == num")" {print $2}')
    else
        STORAGE=""
    fi

    # Validate that a valid storage name was resolved
    if [[ -n "$STORAGE" ]] && echo "$AVAILABLE_STORAGES" | grep -qw "$STORAGE"; then
        echo -e "${WHITE}[INFO] ${GREEN}Selected storage:${WHITE} $STORAGE"
        echo
        break
    else
        echo -e "${WHITE}[ERROR] ${RED}Invalid storage selection. Please choose a valid storage number.${WHITE}"
    fi
done

# Image URL
echo -ne "${GREEN}Enter custom image URL or press Enter to use default [$DEFAULT_IMAGE_URL]: ${WHITE}"
read IMAGE_URL
IMAGE_URL="${IMAGE_URL:-$DEFAULT_IMAGE_URL}"
echo -e "${WHITE}[INFO] ${GREEN}Selected image URL:${WHITE} $IMAGE_URL"
echo

# Username validation
while true; do
   echo -ne "${GREEN}Enter the username for the new user: ${WHITE}"
   read username
   if [[ "$username" =~ ^[a-z_][a-z0-9_-]{2,15}$ ]]; then
       echo -e "${WHITE}[INFO] ${GREEN}Selected username:${WHITE} $username"
       echo
       break
   else
       echo -e "${WHITE}[ERROR] ${RED}Invalid username. Use lowercase letters, numbers, underscores, and hyphens.${WHITE}"
   fi
done

# Password validation
while true; do
   echo -ne "${GREEN}Enter the password for the new user: ${WHITE}"
   read -s user_password
   echo
   echo -ne "${GREEN}Confirm the password: ${WHITE}"
   read -s user_password_confirm
   echo
   if [ -n "$user_password" ] && [ "$user_password" == "$user_password_confirm" ]; then
       echo -e "${WHITE}[INFO] ${GREEN}Password set successfully.${WHITE}"
       echo
       break
   else
       echo -e "${WHITE}[ERROR] ${RED}Passwords do not match or are empty.${WHITE}"
   fi
done

# Verify checksum with error handling
TEMPLATE_DIR="/var/lib/vz/template/iso"
IMAGE_NAME="debian-12-nocloud-amd64.qcow2"
CHECKSUMS_URL="${IMAGE_URL%/*}/SHA512SUMS"
mkdir -p "$TEMPLATE_DIR"
cd "$TEMPLATE_DIR"

# Download checksums and image with force overwrite
wget -q "$CHECKSUMS_URL" -O SHA512SUMS || { echo "[ERROR] Failed to download checksums" && exit 1; }
wget -O "$IMAGE_NAME" "$IMAGE_URL" || { echo "[ERROR] Failed to download image" && exit 1; }

# Verify checksum
if ! grep "$IMAGE_NAME" SHA512SUMS | sha512sum -c --status; then
   echo "[WARNING] Checksum verification failed. Proceeding with caution."
fi

# Customize image
virt-customize -a "$IMAGE_NAME" --install qemu-guest-agent,openssh-server,cloud-init,cloud-initramfs-growroot,cloud-guest-utils,sudo,curl,wget,ntp,cron
virt-customize -a "$IMAGE_NAME" --run-command "truncate -s 0 /etc/machine-id"
virt-customize -a "$IMAGE_NAME" --run-command "passwd -l root"
virt-customize -a "$IMAGE_NAME" --run-command "useradd -m -s /bin/bash $username"
virt-customize -a "$IMAGE_NAME" --run-command "usermod -aG sudo $username"
virt-customize -a "$IMAGE_NAME" --password "$username:password:$user_password"
virt-customize -a "$IMAGE_NAME" --run-command "rm -f /etc/ssh/ssh_host_*"

# Create and configure VM
qm create "$VM_ID" --name "$HOSTNAME" --memory "$MEMORY" --cores "$CORES" --net0 virtio,bridge="$BRIDGE,firewall=1"
qm importdisk "$VM_ID" "$TEMPLATE_DIR/$IMAGE_NAME" "$STORAGE"
qm set "$VM_ID" --scsihw virtio-scsi-single --scsi0 "$STORAGE:vm-${VM_ID}-disk-0,cache=writeback,discard=on,ssd=1"
qm set "$VM_ID" --boot c --bootdisk scsi0
qm set "$VM_ID" --scsi2 "$STORAGE:cloudinit"
qm set "$VM_ID" --agent enabled=1
qm set "$VM_ID" --serial0 socket
qm set "$VM_ID" --vga serial0
qm set "$VM_ID" --cpu cputype=host
qm set "$VM_ID" --ostype l26
qm set "$VM_ID" --ciupgrade 1

# Set initial and minimum memory
qm set "$VM_ID" --memory "$MEMORY" --balloon 2048

# Set cloud-init user
qm set "$VM_ID" --ciuser "$username" --cipassword "$user_password"
qm set "$VM_ID" --ipconfig0 ip=dhcp

echo "VM $VM_ID ($HOSTNAME) created successfully!"
echo
echo "Converting to Template..."
echo
qm template "$VM_ID"
sleep 5
