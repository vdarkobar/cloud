#!/bin/bash

clear

#################################################################
# ANSI escape sequence for green, red, yellow font and no color #
#################################################################

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'


#################
# Intro message #
#################

# Get the short hostname directly
HOSTNAME=$(hostname -s)

# Extract the domain name from /etc/resolv.conf

# Method 1: Using awk
DOMAIN_LOCAL=$(awk -F' ' '/^domain/ {print $2; exit}' /etc/resolv.conf)
if [[ -n "$DOMAIN_LOCAL" ]]; then
    echo -e "${GREEN} Domain name found using:${NC} awk (domain line)"
else
    # Method 2: Using sed
    DOMAIN_LOCAL=$(sed -n 's/^domain //p' /etc/resolv.conf)
    if [[ -n "$DOMAIN_LOCAL" ]]; then
        echo -e "${GREEN} Domain name found using:${NC} sed (domain line)"
    else
        # Backup: Check the 'search' line
        DOMAIN_LOCAL=$(awk -F' ' '/^search/ {print $2; exit}' /etc/resolv.conf)
        if [[ -n "$DOMAIN_LOCAL" ]]; then
            echo -e "${GREEN} Domain name found using:${NC} awk (search line)"
        else
            DOMAIN_LOCAL=$(sed -n 's/^search //p' /etc/resolv.conf)
            if [[ -n "$DOMAIN_LOCAL" ]]; then
                echo -e "${GREEN} Domain name found using:${NC} sed (search line)"
            else
                echo -e "${RED} Domain name not found using available methods .${NC}"
                exit 1
            fi
        fi
    fi
fi

# IP Address extraction

# Method 1: Using hostname -I to get the local IP address
LOCAL_IP=$(hostname -I | awk '{print $1}') # Picks the first IP address
if [[ -n "$LOCAL_IP" ]]; then
    echo -e "${GREEN} IP Address found using:${NC} hostname -I"
else
    # Method 2: Parsing through ip addr show
    LOCAL_IP=$(ip addr show | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | awk '{print $2}' | cut -d/ -f1 | grep -v '127.0.0.1')
    if [[ -n "$LOCAL_IP" ]]; then
        echo -e "${GREEN} IP Address parsed from uotput of:${NC} ip addr show"
    else
        echo -e "${RED} IP Address not found using available methods .${NC}"
    fi
fi

echo
echo -e "${GREEN} This script will install and configure${NC} Nextcloud server"
echo
echo
echo -e "${GREEN} Local IP Address      :${NC} $LOCAL_IP"
echo -e "${GREEN} Machine hostname      :${NC} $HOSTNAME"
echo -e "${GREEN} Local domain          :${NC} $DOMAIN_LOCAL"
echo
echo
echo -e "${GREEN} Be sure that you are logged in as a${NC} non-root ${GREEN}user and that user is added to the${NC} sudo ${GREEN}group"${NC}

sleep 0.5 # delay for 0.5 seconds
echo

echo
echo -e "${GREEN} Login to${NC} CloudFlare ${GREEN}and set${NC} Domain name${GREEN}, or${NC} Domain name ${GREEN}and${NC} Subdomain ${GREEN}for your${NC} NextCloud"
echo
echo "        A   | example.com | YOUR WAN IP"
echo
echo -e "${GREEN} or:${NC}"
echo
echo "        A   | example.com | YOUR WAN IP"
echo "      CNAME |  subdomain  | @ (or example.com)"
echo
echo -e "${GREEN} Add subdomain${NC} code ${GREEN}for${NC} Collabora Office"
echo
echo "      CNAME |     code    | @ (or example.com)"
echo

echo -e "${GREEN} Decide what you will use for: ${NC}"
echo
echo -e " - Public Key to configure your SSH access to container"
echo -e " - Time Zone"
echo -e " - User name and Password for Nextcloud Admin user"
echo -e " - NextCloud Port Number"
echo


#######################################
# Prompt user to confirm script start #
#######################################

while true; do
    read -p "$(echo -e "${YELLOW} Proceed with installation? [Y/n]: ${NC}")" choice
    choice=$(echo "$choice" | tr '[:upper:]' '[:lower:]') # Convert input to lowercase
    echo

    # Set default to "yes" if input is empty
    choice=${choice:-yes}

    case "$choice" in
        y|yes)
            echo -e "${GREEN} Starting...${NC}"
            echo
            sleep 0.5
            break
            ;;
        n|no)
            echo -e "${RED}Aborting script.${NC}"
            exit
            ;;
        *)
            echo -e "${YELLOW}Invalid input. Please enter 'y' or 'n'.${NC}"
            ;;
    esac
done


################## T e m p l a t e  p a r t ##################
### ↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓ ###


####################
# Install Packages #
####################

echo -e "${GREEN} Installing packages... ${NC}"

sleep 0.5 # delay for 0.5 seconds
echo

# Update the package repositories
if ! sudo apt update; then
    echo -e "${RED} Failed to update package repositories. Exiting.${NC}"
    exit 1
fi

# Template packages
if ! sudo apt install -y \
    ufw \
    wget \
    curl \
    gnupg2 \
    argon2 \
    fail2ban \
    lsb-release \
    gnupg-agent \
    libpam-tmpdir \
    bash-completion \
    ca-certificates \
    qemu-guest-agent \
    unattended-upgrades \
    cloud-initramfs-growroot \
    software-properties-common; then
    echo -e "${RED} Failed to install packages. Exiting.${NC}"
    exit 1
fi


#######################
# Create backup files #
#######################

echo
echo -e "${GREEN} Creating backup files${NC}"

sleep 0.5 # delay for 0.5 seconds
echo

# Backup the existing /etc/hosts file
if [ ! -f /etc/hosts.backup ]; then
    sudo cp /etc/hosts /etc/hosts.backup
    echo -e "${GREEN} Backup of${NC} /etc/hosts ${GREEN}created.${NC}"
else
    echo -e "${YELLOW} Backup of${NC} /etc/hosts ${YELLOW}already exists. Skipping backup.${NC}"
fi

# To preserve fail2ban custom settings...
if ! sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local; then
    echo -e "${RED} Failed to copy jail.conf to jail.local. Exiting.${NC}"
    exit 1
fi

# Backup the existing /etc/fail2ban/jail.local file
if [ ! -f /etc/fail2ban/jail.local.backup ]; then
    sudo cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.backup
    echo -e "${GREEN} Backup of${NC} /etc/fail2ban/jail.local ${GREEN}created.${NC}"
else
    echo -e "${YELLOW} Backup of${NC} /etc/fail2ban/jail.local ${YELLOW}already exists. Skipping backup.${NC}"
fi

# Backup the existing /etc/ssh/sshd_config file
if [ ! -f /etc/ssh/sshd_config.backup ]; then
    sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    echo -e "${GREEN} Backup of${NC} /etc/ssh/sshd_config ${GREEN}created.${NC}"
else
    echo -e "${YELLOW} Backup of${NC} /etc/ssh/sshd_config ${YELLOW}already exists. Skipping backup.${NC}"
fi

# Backup the existing /etc/pam.d/sshd file
if [ ! -f /etc/pam.d/sshd.backup ]; then
    sudo cp /etc/pam.d/sshd /etc/pam.d/sshd.backup
    echo -e "${GREEN} Backup of${NC} /etc/pam.d/sshd ${GREEN}created.${NC}"
else
    echo -e "${YELLOW} Backup of${NC} /etc/pam.d/sshd ${YELLOW}already exists. Skipping backup.${NC}"
fi

# Backup the existing /etc/fstab file
if [ ! -f /etc/fstab.backup ]; then
    sudo cp /etc/fstab /etc/fstab.backup
    echo -e "${GREEN} Backup of${NC} /etc/fstab ${GREEN}created.${NC}"
else
    echo -e "${YELLOW} Backup of${NC} /etc/fstab ${YELLOW}already exists. Skipping backup.${NC}"
fi

# Backup the existing /etc/sysctl.conf file
if [ ! -f /etc/sysctl.conf.backup ]; then
    sudo cp /etc/sysctl.conf /etc/sysctl.conf.backup
    echo -e "${GREEN} Backup of${NC} /etc/sysctl.conf ${GREEN}created.${NC}"
else
    echo -e "${YELLOW} Backup of${NC} /etc/sysctl.conf ${YELLOW}already exists. Skipping backup.${NC}"
fi


######################
# Prepare hosts file #
######################

echo
echo -e "${GREEN} Setting up hosts file ${NC}"

sleep 0.5 # delay for 0.5 seconds
echo

# Extract the domain name from /etc/resolv.conf
domain_name=$(awk -F' ' '/^domain/ {print $2; exit}' /etc/resolv.conf)

# Get the host's IP address and hostname
host_ip=$(hostname -I | awk '{print $1}')
host_name=$(hostname)

# Construct the new line for /etc/hosts
new_line="$host_ip $host_name $host_name.$domain_name"

# Create a temporary file with the desired contents
{
    echo "$new_line"
    echo "============================================"
    # Replace the line containing the current hostname with the new line
    awk -v hostname="$host_name" -v new_line="$new_line" '!($0 ~ hostname) || $0 == new_line' /etc/hosts
} > /tmp/hosts.tmp

# Move the temporary file to /etc/hosts
sudo mv /tmp/hosts.tmp /etc/hosts

echo -e "${GREEN} File${NC} /etc/hosts ${GREEN}has been updated ${NC}"
echo


############################################
# Automatically enable unattended-upgrades #
############################################

echo -e "${GREEN} Enabling unattended-upgrades ${NC}"

# Enable unattended-upgrades
if echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | sudo debconf-set-selections && sudo dpkg-reconfigure -f noninteractive unattended-upgrades; then
    echo
    echo -e "${GREEN} Unattended-upgrades enabled successfully.${NC}"
    echo
else
    echo -e "${RED} Failed to enable unattended-upgrades. Exiting.${NC}"
    exit 1
fi

# Define the file path
FILEPATH="/etc/apt/apt.conf.d/50unattended-upgrades"

# Check if the file exists before attempting to modify it
if [ ! -f "$FILEPATH" ]; then
    echo -e "${RED}$FILEPATH does not exist. Exiting.${NC}"
    exit 1
fi

# Uncomment the necessary lines
if sudo sed -i 's|//Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";|Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";|g' $FILEPATH \
   && sudo sed -i 's|//Unattended-Upgrade::Remove-New-Unused-Dependencies "true";|Unattended-Upgrade::Remove-New-Unused-Dependencies "true";|g' $FILEPATH \
   && sudo sed -i 's|//Unattended-Upgrade::Remove-Unused-Dependencies "false";|Unattended-Upgrade::Remove-Unused-Dependencies "true";|g' $FILEPATH \
   && sudo sed -i 's|//Unattended-Upgrade::Automatic-Reboot "false";|Unattended-Upgrade::Automatic-Reboot "true";|g' $FILEPATH \
   && sudo sed -i 's|//Unattended-Upgrade::Automatic-Reboot-Time "02:00";|Unattended-Upgrade::Automatic-Reboot-Time "02:00";|g' $FILEPATH; then
    echo -e "${GREEN} unattended-upgrades configuration updated successfully.${NC}"
    echo
else
    echo -e "${RED} Failed to update configuration. Please check your permissions and file paths. Exiting.${NC}"
    exit 1
fi


#######################
# Setting up Fail2Ban #
#######################

echo -e "${GREEN} Setting up Fail2Ban...${NC}"
echo

# Check if Fail2Ban is installed
if ! command -v fail2ban-server >/dev/null 2>&1; then
    echo -e "${RED} Fail2Ban is not installed. Please install Fail2Ban and try again. Exiting.${NC}"
    exit 1
fi

# Fixing Debian bug by setting backend to systemd
if ! sudo sed -i 's|backend = auto|backend = systemd|g' /etc/fail2ban/jail.local; then
    echo -e "${RED} Failed to set backend to systemd in jail.local. Exiting.${NC}"
    exit 1
fi

echo -e "${GREEN} Configuring Fail2Ban for SSH protection...${NC}"
echo

# Set the path to the sshd configuration file
config_file="/etc/fail2ban/jail.local"

# Use awk to add "enabled = true" below the second [sshd] line (first is a comment)
if ! sudo awk '/\[sshd\]/ && ++n == 2 {print; print "enabled = true"; next}1' "$config_file" > temp_file || ! sudo mv temp_file "$config_file"; then
    echo -e "${RED} Failed to enable SSH protection. Exiting.${NC}"
    exit 1
fi

# Change bantime to 15m
if ! sudo sed -i 's|bantime  = 10m|bantime  = 15m|g' /etc/fail2ban/jail.local; then
    echo -e "${RED} Failed to set bantime to 15m. Exiting.${NC}"
    exit 1
fi

# Change maxretry to 3
if ! sudo sed -i 's|maxretry = 5|maxretry = 3|g' /etc/fail2ban/jail.local; then
    echo -e "${RED} Failed to set maxretry to 3. Exiting.${NC}"
    exit 1
fi

echo -e "${GREEN} Fail2Ban setup completed.${NC}"
sleep 0.5 # delay for 0.5 seconds
echo


##################
# Setting up UFW #
##################

echo -e "${GREEN} Setting up UFW...${NC}"
echo

# Limit SSH to Port 22/tcp
if ! sudo ufw limit 22/tcp comment "SSH"; then
    echo -e "${RED} Failed to limit SSH access. Exiting.${NC}"
    exit 1
fi

# Enable UFW without prompt
if ! sudo ufw --force enable; then
    echo -e "${RED} Failed to enable UFW. Exiting.${NC}"
    exit 1
fi

# Set global rules
if ! sudo ufw default deny incoming || ! sudo ufw default allow outgoing; then
    echo -e "${RED} Failed to set global rules. Exiting.${NC}"
    exit 1
fi

# Reload UFW to apply changes
if ! sudo ufw reload; then
    echo -e "${RED} Failed to reload UFW. Exiting.${NC}"
    exit 1
fi

echo
echo -e "${GREEN} UFW setup completed.${NC}"
sleep 0.5 # delay for 0.5 seconds
echo


##########################
# Securing Shared Memory #
##########################

echo -e "${GREEN} Securing Shared Memory...${NC}"
echo

# Define the line to append
LINE="none /run/shm tmpfs defaults,ro 0 0"

# Append the line to the end of the file
if ! echo "$LINE" | sudo tee -a /etc/fstab > /dev/null; then
    echo -e "${RED} Failed to secure shared memory. Exiting.${NC}"
    exit 1
fi


###############################
# Setting up system variables #
###############################

echo -e "${GREEN} Setting up system variables...${NC}"
echo

# Define the file path
FILEPATH="/etc/sysctl.conf"

# Modify system variables for security enhancements
if ! sudo sed -i 's|#net.ipv4.conf.default.rp_filter=1|net.ipv4.conf.default.rp_filter=1|g' $FILEPATH \
   || ! sudo sed -i 's|#net.ipv4.conf.all.rp_filter=1|net.ipv4.conf.all.rp_filter=1|g' $FILEPATH \
   || ! sudo sed -i 's|#net.ipv4.conf.all.accept_redirects = 0|net.ipv4.conf.all.accept_redirects = 0|g' $FILEPATH \
   || ! sudo sed -i 's|#net.ipv6.conf.all.accept_redirects = 0|net.ipv6.conf.all.accept_redirects = 0|g' $FILEPATH \
   || ! sudo sed -i 's|#net.ipv4.conf.all.send_redirects = 0|net.ipv4.conf.all.send_redirects = 0|g' $FILEPATH \
   || ! sudo sed -i 's|#net.ipv4.conf.all.accept_source_route = 0|net.ipv4.conf.all.accept_source_route = 0|g' $FILEPATH \
   || ! sudo sed -i 's|#net.ipv6.conf.all.accept_source_route = 0|net.ipv6.conf.all.accept_source_route = 0|g' $FILEPATH \
   || ! sudo sed -i 's|#net.ipv4.conf.all.log_martians = 1|net.ipv4.conf.all.log_martians = 1|g' $FILEPATH; then
    echo -e "${RED} Error occurred during system variable configuration. Exiting.${NC}"
    exit 1
fi

# Reload sysctl with the new configuration
if ! sudo sysctl -p; then
    echo
    echo -e "${RED} Failed to reload sysctl configuration. Exiting.${NC}"
    exit 1
fi


####################################
# Obtain Public key for SSH access #
####################################

# Get the username running the script
user=$(whoami)

# Path to the authorized_keys
auth_keys="/home/$user/.ssh/authorized_keys"

# Ensure .ssh directory exists
if [ ! -d "/home/$user/.ssh" ]; then
    echo
    echo -e "${GREEN} Creating .ssh directory...${NC}"
    echo
    sudo mkdir -p "/home/$user/.ssh" || { echo -e "${RED} Error: Failed to create .ssh directory${NC}"; exit 1; }
fi

# Ensure authorized_keys file exists
if [ ! -f "$auth_keys" ]; then
    echo -e "${GREEN} Creating authorized_keys file...${NC}"
    echo
    sudo touch "$auth_keys" || { echo -e "${RED} Error: Failed to create authorized_keys file${NC}"; exit 1; }
fi

# Ask the user for the public key
while true; do
    echo
    echo -e "${YELLOW} Please enter your public SSH key:${NC}"
    echo
    read public_key

    # Check if the input was empty
    if [ -z "$public_key" ]; then
        echo -e "${RED} No input received, please enter a public key.${NC}"
    else
        # Validate the public key format
        if [[ "$public_key" =~ ^ssh-(rsa|dss|ecdsa|ed25519)[[:space:]][A-Za-z0-9+/]+[=]{0,2} ]]; then
            break
        else
            echo -e "${RED} Invalid SSH key format. Please enter a valid SSH public key.${NC}"
        fi
    fi
done

# Append the public key to the authorized_keys
echo "$public_key" | sudo tee -a "$auth_keys" > /dev/null || { echo -e "${RED} Error: Failed to append the public key to authorized_keys${NC}"; exit 1; }

echo
echo -e "${GREEN} Public key added successfully.${NC}"
sleep 0.5 # delay for 0.5 seconds
echo


#################################
# Locking root account password #
#################################

echo -e "${GREEN} Locking root account password...${NC}"
echo

# Attempt to lock the root account password
if ! sudo passwd -l root; then
    echo -e "${RED} Failed to lock root account password. Exiting.${NC}"
    exit 1
fi

sleep 0.5 # delay for 0.5 seconds
echo


############################
# Setting up SSH variables #
############################

echo -e "${GREEN} Setting up SSH variables...${NC}"

# Define the file path
FILEPATH="/etc/ssh/sshd_config"

# Applying multiple sed operations to configure SSH securely. If any fail, an error message will be shown.
if ! (sudo sed -i 's|KbdInteractiveAuthentication no|#KbdInteractiveAuthentication no|g' $FILEPATH \
    && sudo sed -i 's|#LogLevel INFO|LogLevel VERBOSE|g' $FILEPATH \
    && sudo sed -i 's|#PermitRootLogin prohibit-password|PermitRootLogin no|g' $FILEPATH \
    && sudo sed -i 's|#StrictModes yes|StrictModes yes|g' $FILEPATH \
    && sudo sed -i 's|#MaxAuthTries 6|MaxAuthTries 3|g' $FILEPATH \
    && sudo sed -i 's|#MaxSessions 10|MaxSessions 2|g' $FILEPATH \
    && sudo sed -i 's|#IgnoreRhosts yes|IgnoreRhosts yes|g' $FILEPATH \
    && sudo sed -i 's|#PasswordAuthentication yes|PasswordAuthentication no|g' $FILEPATH \
    && sudo sed -i 's|#PermitEmptyPasswords no|PermitEmptyPasswords no|g' $FILEPATH \
    && sudo sed -i 's|UsePAM yes|UsePAM no|g' $FILEPATH \
    && sudo sed -i 's|#GSSAPIAuthentication no|GSSAPIAuthentication no|g' $FILEPATH \
    && sudo sed -i '/# Ciphers and keying/a Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr' $FILEPATH \
    && sudo sed -i '/chacha20-poly1305/a KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256' $FILEPATH \
    && sudo sed -i '/curve25519-sha256/a Protocol 2' $FILEPATH); then
    echo -e "${RED} Failed to configure SSH variables. Exiting.${NC}"
    exit 1
fi

sleep 0.5 # delay for 0.5 seconds
echo

# Disabling ChallengeResponseAuthentication explicitly #
echo -e "${GREEN} Disabling ChallengeResponseAuthentication...${NC}"

# Define the line to append
LINE="ChallengeResponseAuthentication no"
FILEPATH="/etc/ssh/sshd_config"

# Check if the line already exists to avoid duplications
if grep -q "^$LINE" "$FILEPATH"; then
    echo -e "${YELLOW} ChallengeResponseAuthentication is already set to no.${NC}"
else
    # Append the line to the end of the file
    if ! echo "$LINE" | sudo tee -a $FILEPATH > /dev/null; then
        echo -e "${RED} Failed to disable ChallengeResponseAuthentication. Exiting.${NC}"
        exit 1
    fi
fi

sleep 0.5 # delay for 0.5 seconds
echo


#############################################
# Allow SSH only for the current Linux user #
#############################################

echo -e "${GREEN} Allowing SSH only for the current Linux user...${NC}"

# Get the current Linux user
user=$(whoami)
FILEPATH="/etc/ssh/sshd_config"

# Check if "AllowUsers" is already set for the current user to avoid duplications
if grep -q "^AllowUsers.*$user" "$FILEPATH"; then
    echo -e "${YELLOW} SSH access is already restricted to the current user (${user}).${NC}"
else
    # Append the user's username to /etc/ssh/sshd_config
    if ! echo "AllowUsers $user" | sudo tee -a $FILEPATH >/dev/null; then
        echo -e "${RED} Failed to restrict SSH access to the current user. Exiting.${NC}"
        exit 1
    fi
    # Restart SSH to apply changes
    if ! sudo systemctl restart ssh; then
        echo -e "${RED} Failed to restart SSH service. Exiting.${NC}"
        exit 1
    fi
fi

sleep 0.5 # delay for 0.5 seconds
echo


################
# Restart sshd #
################

echo -e "${GREEN} Restarting sshd...${NC}"

# Attempt to restart the sshd service
if ! sudo systemctl restart sshd; then
    echo -e "${RED} Failed to restart sshd. Please check the service status and logs for more details. Exiting.${NC}"
    exit 1
fi

sleep 0.5 # delay for 0.5 second
echo


################## A p p l i c a t i o n  p a r t ##################
### ↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓ ###


##########################################
# Install Docker and Docker Compose (v2) #
##########################################

# Manually Stop the unattended-upgr Process (if running)
# Stops the automatic updates temporarily, allowing install to proceed
sudo systemctl stop unattended-upgrades

echo -e "${GREEN} Starting the installation of Docker and Docker Compose (v2)...${NC}"
echo

# Update apt package index
sudo apt-get update || { echo -e "${RED} Failed to update package index${NC}"; exit 1; }

# Install prerequisites
sudo apt-get install -y ca-certificates curl gnupg lsb-release || { echo -e "${RED} Failed to install prerequisites${NC}"; exit 1; }

# Add Docker’s official GPG key
sudo mkdir -p /etc/apt/keyrings && curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg || { echo -e "${RED} Failed to add Docker GPG key${NC}"; exit 1; }

# Set up the Docker repository
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null || { echo -e "${RED} Failed to set up Docker repository${NC}"; exit 1; }

# Update the apt package index again
sudo apt-get update || { echo -e "${RED} Failed to update package index after adding Docker repository${NC}"; exit 1; }

# Install Docker Engine, CLI, containerd, and Compose plugin
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin || { echo -e "${RED} Failed to install Docker components${NC}"; exit 1; }

# Add current user to Docker Group
sudo usermod -aG docker $(whoami) || { echo -e "${RED} Failed to add the current user to the Docker group${NC}"; exit 1; }

# Verify installation
sudo docker --version && docker compose version || { echo -e "${RED} Docker installation verification failed${NC}"; exit 1; }

# ensure package manager status is okay
sudo dpkg --configure -a

echo
echo -e "${GREEN} Docker and Docker Compose(v2) installation completed.${NC}"
echo


################################
# Setting up working directory #
################################

# Create directories
mkdir -p "$HOME/nextcloud" "$HOME/nextcloud/.secrets" || { echo -e "${RED} Failed to create directories${NC}"; exit 1; }

# Notify the creation of the directories
echo -e "${GREEN} Created directories: 'nextcloud', 'nextcloud/.secrets'${NC}"

# Set the WORK_DIR variable
WORK_DIR=$HOME/nextcloud

echo
echo -e "${GREEN} Working directory:${NC} $WORK_DIR"
echo


##############################
# Create docker-compose file #
##############################

# Define the path to the directory and the file
file_path="$WORK_DIR/docker-compose.yml"

# Check if the WORK_DIR variable is set
if [ -z "$WORK_DIR" ]; then
    echo -e "${RED} Error: WORK_DIR variable is not set${NC}"
    exit 1
fi

# Create or overwrite the docker-compose.yml file, using sudo for permissions
echo -e "${GREEN} Creating docker-compose file...:${NC} $file_path"

sudo tee "$file_path" > /dev/null <<EOF || { echo "Error: Failed to create $file_path"; exit 1; }
networks:
  nc:
    name: nc
    driver: bridge
  db:
    name: db
    driver: bridge

secrets:
  mysql_root_password:
    file: ./.secrets/mysql_root_password.secret
  nc_mysql_password:
    file: ./.secrets/nc_mysql_password.secret
  nc_admin_user:
    file: ./.secrets/nc_admin_user.secret
  nc_admin_password:
    file: ./.secrets/nc_admin_password.secret

services:

  # MariaDB - The open source relational database.
  db:
    image: mariadb:latest
    command: --skip-innodb-read-only-compressed
    container_name: nextcloud-db # change for multiple instances
    restart: always

    networks:
      - db

    secrets: 
      - mysql_root_password
      - nc_mysql_password

    volumes:
      - ./nextcloud-db-data:/var/lib/mysql

    environment:
      - TZ=\$TZ
      - MYSQL_ROOT_PASSWORD_FILE=/run/secrets/mysql_root_password
      - MYSQL_DATABASE=db
      - MYSQL_USER=dbuser
      - MYSQL_PASSWORD_FILE=/run/secrets/nc_mysql_password

  # Redis - Key-value Store
  redis:
    image: redis:latest
    restart: always

    networks:
      - db
      - nc

    volumes:
      - ./redis:/var/lib/redis

  # NextCloud - The self-hosted productivity platform.
  nextcloud:
    image: nextcloud:stable 
    container_name: nextcloud # change for multiple instances
    restart: always

    networks:
      - nc
      - db

    ports:
      - \$NCPORTN:80

    depends_on:
      - redis
      - db

    secrets: 
      - nc_mysql_password
      - nc_admin_user
      - nc_admin_password

    volumes:
      - ./files:/var/www/html

    environment:
      - REDIS_HOST=redis
      - MYSQL_HOST=db:3306
      - MYSQL_DATABASE=db
      - MYSQL_USER=dbuser
      - MYSQL_PASSWORD_FILE=/run/secrets/nc_mysql_password
      - NEXTCLOUD_ADMIN_PASSWORD_FILE=/run/secrets/nc_admin_password
      - NEXTCLOUD_ADMIN_USER_FILE=/run/secrets/nc_admin_user
      - NEXTCLOUD_TRUSTED_DOMAINS=\$SUBDOMAIN\$DOMAINNAME www.\$DOMAINNAME \$LOCALIP # space separated list

  # Collabora - Document Server
  # Connect NextCloud to Collabora app with: https://code.DOMAINNAME
  # Admin console at https://<office-domain>/loleaflet/dist/admin/admin.html
  code:
    container_name: code # change for multiple instances
    image: collabora/code:latest
    restart: always
#    security_opt:
#      - no-new-privileges:true
    cap_add:
      - MKNOD

    networks:
      - nc

    ports:
      - "9980:9980"

    volumes:
      - /etc/timezone:/etc/timezone:ro
      - /etc/localtime:/etc/localtime:ro

    environment:
      - username=\$MY_USERNAME
      - password=\$MY_PASSWORD
      - domain=\$SUBDOMAIN\$DOMAINNAME #\$MY_CODE_DOMAIN #<your-NEXTCLOUD-dot-escaped-domain>
      - VIRTUAL_HOST=code.\$DOMAINNAME
      - LETSENCRYPT_HOST=code.\$DOMAINNAME
#      - server_name=code.\$DOMAINNAME
      - extra_params=--o:ssl.enable=false --o:ssl.termination=true

  # Watchtower - automating Docker container base image updates.
  watchtower:
    image: containrrr/watchtower
    container_name: watchtower-nc
    restart: always

    networks:
      - nc
      - db

    volumes:
      - /var/run/docker.sock:/var/run/docker.sock

    environment:
      - TZ=\$TZ
      - WATCHTOWER_DEBUG=true
      - WATCHTOWER_CLEANUP=true
      - WATCHTOWER_REMOVE_VOLUMES=true
      - WATCHTOWER_INCLUDE_STOPPED=true
      - WATCHTOWER_SCHEDULE=0 30 5 * * * # Everyday at 5:30
EOF

# Check if the file was created successfully
if [ $? -ne 0 ]; then
    echo
    echo -e "${RED} Error: Failed to create${NC} $file_path"
    exit 1
fi

echo
echo -e "${GREEN} docker-compose file created successfully:${NC} $file_path"
echo


####################
# Create .env file #
####################

# Define the path to the directory and the file
file_path="$WORK_DIR/.env"

# Check if the WORK_DIR variable is set
if [ -z "$WORK_DIR" ]; then
    echo -e "${RED} Error: WORK_DIR variable is not set${NC}"
    exit 1
fi

# Create or overwrite the docker-compose.yml file, using sudo for permissions
echo -e "${GREEN} Creating .env file...:${NC} $file_path"

sudo tee "$file_path" > /dev/null <<EOF || { echo "Error: Failed to create $file_path"; exit 1; }
TZ=01
DOMAINNAME=02
SUBDOMAIN=03
LOCALIP=04
MY_USERNAME=05
NCPORTN=06
MY_PASSWORD=07
EOF

# Check if the file was created successfully
if [ $? -ne 0 ]; then
    echo
    echo -e "${RED} Error: Failed to create${NC} $file_path"
    exit 1
fi

echo
echo -e "${GREEN} .env file created successfully:${NC} $file_path"
echo


#############
# Nextcloud #
#############

# Check if timedatectl is available
if ! command -v timedatectl &> /dev/null; then
    echo -e "${RED}Error: timedatectl command not found.${NC}"
    exit 1
fi

DEFAULT_TZ="Europe/Berlin"
TZONES="$(timedatectl list-timezones 2>/dev/null)"

# Check if TZONES retrieval succeeded
if [ $? -ne 0 ] || [ -z "$TZONES" ]; then
    echo -e "${RED}Error: Failed to retrieve list of time zones.${NC}"
    exit 1
fi

while true; do
    echo -ne "${YELLOW} Enter Time Zone (default: $DEFAULT_TZ): ${NC}"
    if ! read TZONE; then
        echo -e "${RED}Error: Failed to read input.${NC}"
        exit 1
    fi

    if [ -z "$TZONE" ]; then
        TZONE="$DEFAULT_TZ"
    fi

    # Validate timezone
    echo
    if echo "$TZONES" | grep -q "^$TZONE$"; then
        echo -e "${GREEN} Time Zone selected: $TZONE${NC}"
        echo
        break
    else
        echo -e "${RED} Invalid Time Zone. Please try again.${NC}"
    fi
done

echo -ne "${YELLOW} Enter Domain name (e.g. example.com): ${NC}"; read DNAME
echo
echo -ne "${YELLOW} Enter Subdomain with . (dot) at the end, or just press Enter to default to Domain name: ${NC}"; read SDNAME
echo
echo -ne "${YELLOW} Enter NextCloud Admin username: ${NC}"; read NCUNAME
echo
#read -s -p "Enter Nextcloud Admin password: " NAPASS

# Nextcloud Admin password
while true; do
    echo -e "${YELLOW} Enter Nextcloud Admin password:${NC}"
    read -s NAPASS
    echo -e "${YELLOW} Retype Nextcloud Admin password:${NC}"
    read -s NAPASS_CONFIRM
    echo

    if [[ "$NAPASS" == "$NAPASS_CONFIRM" ]]; then
        if [[ -z "$NAPASS" ]]; then
            echo -e "${RED}Error: Password cannot be empty. Please try again.${NC}"
        else
            echo -e "${GREEN} Password confirmed successfully.${NC}"
            break
        fi
    else
        echo -e "${RED}Error: Passwords do not match. Please try again.${NC}"
    fi
done

echo
echo -ne "${YELLOW} Enter Collabora username: ${NC}"; read CUNAME
echo
echo -ne "${YELLOW} Enter NextCloud Port Number(49152-65535):${NC} "; read NCPORTN;
# Check if the port number is within the specified range
while [[ $NCPORTN -lt 49152 || $NCPORTN -gt 65535 ]]; do
    echo -e "${RED} Port number is out of the allowed range. Please enter a number between 49152 and 65535.${NC}"
    echo -ne "${GREEN} Enter NPM Port Number(49152-65535):${NC} "; read NCPORTN;
done
echo

# Get the primary local IP address of the machine more reliably
LIP=$(ip route get 1.1.1.1 | awk '{print $7; exit}')

# Update .env file with user input, checking for errors
sed -i "s|01|${TZONE}|" $WORK_DIR/.env || { echo -e "${RED} Failed to update Time Zone in .env file.${NC}"; exit 1; }
sed -i "s|02|${DNAME}|" $WORK_DIR/.env || { echo -e "${RED} Failed to update Domain Name in .env file.${NC}"; exit 1; }
sed -i "s|03|${SDNAME}|" $WORK_DIR/.env || { echo -e "${RED} Failed to update Subdomain in .env file.${NC}"; exit 1; }
sed -i "s|04|${LIP}|" $WORK_DIR/.env || { echo -e "${RED} Failed to update Local IP Address in .env file.${NC}"; exit 1; }
sed -i "s|05|${CUNAME}|" $WORK_DIR/.env || { echo -e "${RED} Failed to update Collabora username in .env file.${NC}"; exit 1; }
sed -i "s|06|${NCPORTN}|" $WORK_DIR/.env || { echo -e "${RED} Failed to update NextCloud Port Number in .env file.${NC}"; exit 1; }
sed -i "s|07|${NAPASS}|" $WORK_DIR/.env || { echo -e "${RED} Failed to update .env file with NextCloud admin password.${NC}"; exit 1; }

# Generate and store secrets, ensuring .secrets directory exists before generating secrets
mkdir -p $WORK_DIR/.secrets || { echo -e "${RED} Failed to create secrets directory.${NC}"; exit 1; }

echo $NCUNAME > $WORK_DIR/.secrets/nc_admin_user.secret || { echo -e "${RED} Failed to store NextCloud admin username.${NC}"; exit 1; }
echo $NAPASS > $WORK_DIR/.secrets/nc_admin_password.secret || { echo -e "${RED} Failed to store NextCloud admin password.${NC}"; exit 1; }
echo $CUNAME > $WORK_DIR/.secrets/collabora_admin_user.secret || { echo -e "${RED} Failed to store Collabora admin username.${NC}"; exit 1; }

echo | openssl rand -base64 48 > $WORK_DIR/.secrets/mysql_root_password.secret || { echo -e "${RED} Failed to generate MySQL root password.${NC}"; exit 1; }
echo | openssl rand -base64 20 > $WORK_DIR/.secrets/nc_mysql_password.secret || { echo -e "${RED} Failed to generate NextCloud MySQL password.${NC}"; exit 1; }


#######
# UFW #
#######

echo -e "${GREEN} Preparing firewall for local access...${NC}"
sleep 0.5 # delay for 0.5 seconds
echo

# Use the PORTN variable for the UFW rule
if ! sudo ufw allow "${NCPORTN}/tcp" comment "Nextcloud custom port"; then
    echo -e "${RED} Failed to open custom port. Exiting.${NC}"
    exit 1
fi

# Reload UFW to apply changes
if ! sudo ufw reload; then
    echo -e "${RED} Failed to reload UFW. Exiting.${NC}"
    exit 1
fi


######################
# Run docker compose #
######################

# Main loop for docker compose up command
echo
while true; do
    read -p "$(echo -e "${YELLOW} Execute docker compose now? [Y/n]: ${NC}")" yn
    yn=$(echo "$yn" | tr '[:upper:]' '[:lower:]') # Convert input to lowercase

    # Set default to "yes" if input is empty
    yn=${yn:-yes}
    echo
    
    case $yn in
        y|yes)
            if ! sudo docker compose --env-file "$WORK_DIR/.env" -f "$WORK_DIR/docker-compose.yml" up -d; then
                echo -e "${RED}Docker compose up failed. Check Docker and Docker Compose installation.${NC}"
                exit 1
            fi
            break
            ;;
        n|no)
            echo -e "${RED}Aborting...${NC}"
            exit
            ;;
        *)
            echo -e "${YELLOW}Invalid input. Please enter 'y' or 'n'.${NC}"
            ;;
    esac
done

# Update permissions
sudo chown -R root:root $WORK_DIR/.secrets/ && sudo chmod -R 600 $WORK_DIR/.secrets/ || { echo -e "${RED} Failed to update secrets directory permissions.${NC}"; exit 1; }


##########
# Access #
##########

# Get the short hostname directly
echo
HOSTNAME=$(hostname -s)

# Extract the domain name from /etc/resolv.conf

# Method 1: Using awk
DOMAIN_LOCAL=$(awk -F' ' '/^domain/ {print $2; exit}' /etc/resolv.conf)
if [[ -n "$DOMAIN_LOCAL" ]]; then
    echo -e "${GREEN} Domain name found using:${NC} awk (domain line)"
else
    # Method 2: Using sed
    DOMAIN_LOCAL=$(sed -n 's/^domain //p' /etc/resolv.conf)
    if [[ -n "$DOMAIN_LOCAL" ]]; then
        echo -e "${GREEN} Domain name found using:${NC} sed (domain line)"
    else
        # Backup: Check the 'search' line
        DOMAIN_LOCAL=$(awk -F' ' '/^search/ {print $2; exit}' /etc/resolv.conf)
        if [[ -n "$DOMAIN_LOCAL" ]]; then
            echo -e "${GREEN} Domain name found using:${NC} awk (search line)"
        else
            DOMAIN_LOCAL=$(sed -n 's/^search //p' /etc/resolv.conf)
            if [[ -n "$DOMAIN_LOCAL" ]]; then
                echo -e "${GREEN} Domain name found using:${NC} sed (search line)"
            else
                echo -e "${RED} Domain name not found using available methods .${NC}"
                exit 1
            fi
        fi
    fi
fi

# IP Address extraction

# Method 1: Using hostname -I to get the local IP address
LOCAL_IP=$(hostname -I | awk '{print $1}') # Picks the first IP address
if [[ -n "$LOCAL_IP" ]]; then
    echo -e "${GREEN} IP Address found using:${NC} hostname -I"
else
    # Method 2: Parsing through ip addr show
    LOCAL_IP=$(ip addr show | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | awk '{print $2}' | cut -d/ -f1 | grep -v '127.0.0.1')
    if [[ -n "$LOCAL_IP" ]]; then
        echo -e "${GREEN} IP Address parsed from uotput of:${NC} ip addr show"
    else
        echo -e "${RED} IP Address not found using available methods .${NC}"
    fi
fi

# Directly concatenate HOSTNAME and DOMAIN, leveraging shell parameter expansion for conciseness
LOCAL_DOMAIN="${HOSTNAME}${DOMAIN_LOCAL:+.$DOMAIN_LOCAL}"

# Display access instructions
echo
echo -e "${GREEN} Local access:${NC} $LOCAL_IP:$NCPORTN"
echo -e "${GREEN}             :${NC} $LOCAL_DOMAIN:$NCPORTN"
echo
echo -e "${GREEN} External access:${NC} $SDNAME$DNAME"
echo
echo -e "${GREEN} Set Collabora Office url in the Nextcloud office app:${NC} https://code.$DNAME"
echo
echo -e "${GREEN} Configure Reverse proxy${NC} (NPM) ${GREEN}for external access.${NC}"
echo

# Define the path to config.php
WORK_DIR=$HOME/nextcloud
CONFIG_PATH="$WORK_DIR/files/config/config.php"
FULL_DOMAIN=$SDNAME$DNAME

echo
echo -e "${GREEN} Run this command to configure${NC} config.php ${GREEN}if using only domain name:${NC} $DNAME"
echo
echo "sudo sed -i \"s|'overwrite.cli.url' => 'http://localhost',|'overwrite.cli.url' => 'https://$DNAME', 'overwritehost' => '$DNAME', 'overwriteprotocol' => 'https',|g\" \"$CONFIG_PATH\""
echo
echo -e "${GREEN} or${NC}"
echo
echo -e "${GREEN} Run this command to configure${NC} config.php ${GREEN}if using subdomain:${NC} ${FULL_DOMAIN}"
echo
echo "sudo sed -i \"s|'overwrite.cli.url' => 'http://localhost',|'overwrite.cli.url' => 'https://${FULL_DOMAIN}', 'overwritehost' => '${FULL_DOMAIN}', 'overwriteprotocol' => 'https',|g\" \"$CONFIG_PATH\""
echo

##########################
# Prompt user for reboot #
##########################

while true; do
    read -p "Do you want to reboot the server now (recommended)? (yes/no): " response
    echo
    case "${response,,}" in
        yes|y) echo -e "${GREEN} Rebooting the server...${NC}"; sudo reboot; break ;;
        no|n) echo -e "${RED} Reboot cancelled.${NC}"; exit 0 ;;
        *) echo -e "${YELLOW} Invalid response. Please answer${NC} yes or no."; echo ;;
    esac
done
