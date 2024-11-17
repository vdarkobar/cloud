#!/bin/bash

# Define color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Script start
echo
echo -e "${GREEN} Proxmox VE:${NC}"
sleep 1
echo -e "${GREEN}  Script creates a new LXC container with a non-root user for enhanced security${NC}"
echo

# Get storage information
#storage_list=$(pvesm status | awk 'NR>1 {print NR-1 " " $1}')
storage_list=$(pvesm status -content vztmpl | awk 'NR>1 {print NR-1 " " $1}')    # new command for testing

if [ -z "$storage_list" ]; then
    echo -e "${RED} No storage found or failed to retrieve storage status.${NC}"
    exit 1
fi

# Display available storage
echo -e "${YELLOW} Available Template storage:${NC}"
echo "$storage_list"
echo

# Ask user where to download the template
while true; do
    echo -e "${YELLOW} Select the storage by selecting the corresponding number: ${NC}"
    read template_storage_number
    template_storage=$(echo "$storage_list" | awk -v num=$template_storage_number '$1 == num {print $2}')
    if [ -z "$template_storage" ]; then
        echo -e "${RED} Invalid selection, please try again.${NC}"
    else
        echo -e "${GREEN} Template will be downloaded to:${NC}" $template_storage
        break
    fi
done

echo

# Get storage information
#storage_list=$(pvesm status | awk 'NR>1 {print NR-1 " " $1}')
storage_list=$(pvesm status -content images | awk 'NR>1 {print NR-1 " " $1}')    # new command for testing

if [ -z "$storage_list" ]; then
    echo -e "${RED} No storage found or failed to retrieve storage status.${NC}"
    exit 1
fi

# Display available storage
echo -e "${YELLOW} Available LXC rootfs storage:${NC}"
echo "$storage_list"
echo

# Ask user where to store container rootfs
while true; do
    echo -e "${YELLOW} Select the storage by selecting the corresponding number: ${NC}"
    read template_rootfs
    template_storage_rootfs=$(echo "$storage_list" | awk -v num=$template_rootfs '$1 == num {print $2}')
    if [ -z "$template_storage_rootfs" ]; then
        echo -e "${RED} Invalid selection, please try again.${NC}"
    else
        echo -e "${GREEN} Container rootfs will be stored on:${NC}" $template_storage_rootfs
        break
    fi
done

echo

# Get next Container ID
echo -e "${YELLOW} Retrieving the next available container ID...${NC}"
container_id=$(pvesh get /cluster/nextid)
if [ $? -ne 0 ] || [ -z "$container_id" ]; then
    echo -e "${RED} Failed to retrieve the next available container ID. Please check Proxmox VE cluster status or your network connection.${NC}"
    exit 1
fi

echo
echo -e "${GREEN} Next available container ID is:${NC}" $container_id
echo

# Prompt for hostname with all necessary checks
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

while true; do
    echo -e "${YELLOW} Please enter a hostname: ${NC}"
    read hstnme

    if [[ -z "$hstnme" ]]; then
        echo -e "${RED} Error: Hostname cannot be empty.${NC}"
        continue
    fi

    if is_reserved_name "$hstnme"; then
        echo -e "${RED} Error: '$hstnme' is a reserved name. Please choose a different hostname.${NC}"
        continue
    fi

    if ! [[ "$hstnme" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,251}[a-zA-Z0-9])?$ ]]; then
        echo -e "${RED} Error: Invalid hostname format. Hostnames must start and end with a letter or digit and can contain hyphens.${NC}"
        continue
    fi

    echo
    echo -e "${GREEN} Hostname${NC} $hstnme ${GREEN}is valid and accepted.${NC}"
    echo
    break
done

# Loop until a valid username is entered
while true; do
    echo -e "${YELLOW} Please enter username for a non-root user: ${NC}"
    read username

    # Check for 'root' username
    if [ "$username" == "root" ]; then
        echo
        echo -e "${RED} Error: 'root' is not an allowed username.${NC}"
        echo
        continue
    fi

    # Validate username: must start with a letter or underscore, followed by letters, digits, dashes, or underscores
    if [[ "$username" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
        # Check if user already exists
        if id "$username" &>/dev/null; then
            echo
            echo -e "${RED} Error: User '$username' already exists.${NC}"
            echo
        else
            # Valid user which does not exist, so break the loop
            break
        fi
    else
        echo -e "${RED} Error: Invalid username. Use only lowercase letters, digits, dashes, and underscores, starting with a letter or an underscore.${NC}"
    fi
done

# Loop until a valid password is entered
while true; do
    echo
    echo -e "${YELLOW} Please enter a password for user '${username}': ${NC}"
    read -s password
    echo
    echo -e "${YELLOW} Please re-enter the password for verification: ${NC}"
    read -s password2

    # Check if passwords match
    if [ "$password" != "$password2" ]; then
        echo
        echo -e "${RED} Error: Passwords do not match. Please try again.${NC}"
        continue
    fi

    # Validate password length and optionally complexity
    if [ ${#password} -lt 8 ]; then
        echo
        echo -e "${RED} Error: Password must be at least 8 characters long.${NC}"
        echo
    else
        # Optionally, check for numeric and special characters
        if ! [[ "$password" =~ [0-9] ]] || ! [[ "$password" =~ [^a-zA-Z0-9] ]]; then
            echo -e "${RED} Error: Password must contain at least one number and one special character.${NC}"
            echo
        else
            # Password is valid
            break
        fi
    fi
done

echo
echo -e "${GREEN} Username${NC} '${username}' ${GREEN}and password set successfully.${NC}"
echo

# Update template list
if ! pveam update; then
    echo -e "${RED} Failed to update template list. Please check your network or repository configuration.${NC}"
    exit 1
fi

echo

# Retrieve the latest Debian LXC template name
#latest_debian_template=$(pveam available --section system | grep debian | sort -r | head -n 1 | awk '{print $2}')
latest_debian_template=$(pveam available --section system | awk '/debian/ {print $2}' | sort -V | tail -n 1)

if [ -z "$latest_debian_template" ]; then
    echo -e "${RED} No Debian templates available for download. Please check your Proxmox repository settings or network connection.${NC}"
    exit 1
fi

echo -e "${YELLOW} Downloading${NC} $latest_debian_template ${YELLOW}to${NC} $template_storage${YELLOW}...${NC}"
echo
if ! pveam download $template_storage $latest_debian_template; then
    echo -e "${RED} Failed to download the template. Please check your storage configuration and network connection, and ensure the template is still available in the repository.${NC}"
    exit 1
fi

echo
echo -e "${GREEN} Template${NC} $latest_debian_template ${GREEN}downloaded successfully to${NC} $template_storage${NC}"
echo

# Assume $latest_debian_template is defined elsewhere in the script
echo -e "${YELLOW} Searching for the Debian template in the filesystem...${NC}"
template_path=$(find / -name "$latest_debian_template" 2>/dev/null)

# Check if the find command was successful and if the template path is not empty
if [ -z "$template_path" ]; then
    echo -e "${RED} Failed to locate the template:${NC}" $latest_debian_template
    echo -e "${RED} Please check the template name and ensure it has been downloaded.${NC}"
    exit 1
fi

echo
echo -e "${GREEN} Template located at:${NC}" $template_path
echo

################
# Creating LXC #
################

# Create LXC and add non-root user
pct create $container_id $template_path \
    --arch amd64 \
    --ostype debian \
    --hostname $hstnme \
    --unprivileged 1 \
    --features nesting=1 \
    --password $password \
    --ignore-unpack-errors \
    --ssh-public-keys /root/.ssh/authorized_keys \
    --ostype debian \
    --storage $template_storage_rootfs \
    --rootfs $template_storage_rootfs:8 \
    --cores 4 \
    --memory 4096 \
    --swap 512 \
    --net0 name=eth0,bridge=vmbr0,firewall=1,ip=dhcp \
    --start 1
sleep 3 && \
pct exec $container_id -- bash -c "
apt update -y && \
apt upgrade -y && \
apt install -y sudo && \
adduser --gecos ',,,,' --disabled-password $username && \
usermod -aG sudo $username && \
echo '$username:$password' | chpasswd
"
# Extracting LXC IP
LOCAL_IP=$(pct exec $container_id -- ip addr show eth0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)

# Setting up LXC description
echo "description: <div align='center'><a href='http://$LOCAL_IP' target='_blank'><img src='https://github.com/vdarkobar/Home-Cloud/blob/main/shared/rsz_debian-logo.png?raw=true'/><br>$LOCAL_IP</a></div>" >> /etc/pve/lxc/$container_id.conf

# Rebooting LXC
pct reboot $container_id
