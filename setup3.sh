#!/bin/bash

clear

##############################################################
# Define ANSI escape sequence for green, red and yellow font #
##############################################################

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'

########################################################
# Define ANSI escape sequence to reset font to default #
########################################################

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
echo -e "${GREEN} Securely access remote instances with a Bastion Host|Jump Server ${NC}"
echo
echo
echo -e "${GREEN} Local IP Address      :${NC} $LOCAL_IP"
echo -e "${GREEN} Machine hostname      :${NC} $HOSTNAME"
echo -e "${GREEN} Local domain          :${NC} $DOMAIN_LOCAL"
echo
echo
echo -e "${GREEN} REMEMBER: ${NC}"
echo
echo -e "${GREEN} - You should be on a clean Debian Server VM/CT install before running this script ${NC}"
echo -e "${GREEN} - You should be logged in as a non root user ${NC}"
echo -e "${GREEN} - Check local domain before changes are applied to hosts file${NC}"
echo


######################################
# Prompt user to confirm script start#
######################################

while true; do
    echo -e "${GREEN} Start Linux Server Hardening?${NC} (yes/no)"
    echo
    read choice

    # Convert choice to lowercase
    choice=${choice,,} # This makes the script case insensitive

    if [[ "$choice" == "yes" || "$choice" == "y" ]]; then
        echo
        echo -e "${GREEN} Updating the apt package index and installing necessary packages ${NC}"
        echo
        sleep 0.5 # delay for 0.5 seconds
        if sudo apt update && sudo apt install -y \
            ufw \
            gnupg2 \
            fail2ban \
            libpam-tmpdir \
            qemu-guest-agent \
            unattended-upgrades \
            libpam-google-authenticator; then
            echo
            echo -e "${GREEN} Done. ${NC}"
            sleep 0.5 # delay for 0.5 second
            echo
            break
        else
            echo -e "${RED} Failed to update or install packages. Please check your connection or package names. ${NC}"
            exit 1
        fi
    elif [[ "$choice" == "no" || "$choice" == "n" ]]; then
        echo -e "${RED} Aborting script. ${NC}"
        exit
    else
        echo
        echo -e "${YELLOW} Invalid input. Please enter${NC} 'yes' or 'no'"
        echo
    fi
done


######################################################################
# Creating a backup of files before making changes using the script. #
######################################################################


# Copy /etc/apt/apt.conf.d/50unattended-upgrades
if ! sudo cp /etc/apt/apt.conf.d/50unattended-upgrades /etc/apt/apt.conf.d/50unattended-upgrades.bak; then
    echo -e "${RED} Error copying 50unattended-upgrades. Exiting.${NC}"
    exit 1
fi

# Copy /etc/ssh/sshd_config
if ! sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak; then
    echo -e "${RED} Error copying sshd_config. Exiting.${NC}"
    exit 1
fi

# Copy /etc/fstab
if ! sudo cp /etc/fstab /etc/fstab.bak; then
    echo -e "${RED} Error copying fstab. Exiting.${NC}"
    exit 1
fi

# Copy /etc/sysctl.conf
if ! sudo cp /etc/sysctl.conf /etc/sysctl.conf.bak; then
    echo -e "${RED} Error copying sysctl.conf. Exiting.${NC}"
    exit 1
fi

# Copy /etc/pam.d/sshd
if ! sudo cp /etc/pam.d/sshd /etc/pam.d/sshd.bak; then
    echo -e "${RED} Error copying sshd in pam.d. Exiting.${NC}"
    exit 1
fi

# Copy /etc/sysctl.conf (second occurrence, for backup)
if ! sudo cp /etc/sysctl.conf /etc/sysctl.bak; then
    echo -e "${RED} Error copying sysctl.conf for the second backup. Exiting.${NC}"
    exit 1
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

sleep 0.5 # delay for 0.5 seconds

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
    echo -e "${GREEN} Configuration updated successfully.${NC}"
    echo
else
    echo -e "${RED} Failed to update configuration. Please check your permissions and file paths. Exiting.${NC}"
    exit 1
fi

sleep 0.5 # delay for 0.5 second


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


#######################
# Setting up Fail2Ban #
#######################

echo -e "${GREEN} Setting up Fail2Ban...${NC}"

# Check if Fail2Ban is installed
if ! command -v fail2ban-server >/dev/null 2>&1; then
    echo -e "${RED} Fail2Ban is not installed. Please install Fail2Ban and try again. Exiting.${NC}"
    exit 1
fi

# To preserve your custom settings...
if ! sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local; then
    echo -e "${RED} Failed to copy jail.conf to jail.local. Exiting.${NC}"
    exit 1
fi


# Copy /etc/fail2ban/jail.local
if ! sudo cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.bak; then
    echo -e "${RED}Error copying jail.local. Exiting.${NC}"
    exit 1
fi

# Fixing Debian bug by setting backend to systemd
if ! sudo sed -i 's|backend = auto|backend = systemd|g' /etc/fail2ban/jail.local; then
    echo -e "${RED} Failed to set backend to systemd in jail.local. Exiting.${NC}"
    exit 1
fi

echo
echo -e "${GREEN} Configuring Fail2Ban for SSH protection...${NC}"

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

echo
echo -e "${GREEN} Fail2Ban setup completed.${NC}"
sleep 0.5 # delay for 0.5 seconds
echo


##########################
# Securing Shared Memory #
##########################

echo -e "${GREEN} Securing Shared Memory...${NC}"

# Define the line to append
LINE="none /run/shm tmpfs defaults,ro 0 0"

# Append the line to the end of the file
if ! echo "$LINE" | sudo tee -a /etc/fstab > /dev/null; then
    echo -e "${RED} Failed to secure shared memory. Exiting.${NC}"
    exit 1
fi

sleep 0.5 # delay for 0.5 seconds
echo


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
    echo -e "${RED}Error occurred during system variable configuration. Exiting.${NC}"
    exit 1
fi

# Reload sysctl with the new configuration
if ! sudo sysctl -p; then
    echo -e "${RED} Failed to reload sysctl configuration. Exiting.${NC}"
    exit 1
fi

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


######################################################
# Editing the PAM configuration for the SSHD Service #
######################################################

  echo -e "${GREEN} Editing the PAM configuration for the SSHD Service ${NC}"

  # Define the file path
  FILEPATH="/etc/pam.d/sshd"

  # Change the default auth so that SSH won’t prompt users for a password if they don’t present a 2-factor token, comment out:
  # Standard Un*x authorization
  sudo sed -i 's|@include common-auth|#@include common-auth|g' $FILEPATH

  echo -e "${GREEN} Done. ${NC}"
  sleep 1 # delay for 1 seconds

  echo

  # Tell SSH to require the use of 2-factor auth
  echo -e "${GREEN} Making SSH to require the use of 2-factor auth ${NC}"
  # Define the line to append
  LINE="auth required pam_google_authenticator.so nullok"

  # Append the line to the end of the file
  echo "$LINE" | sudo tee -a /etc/pam.d/sshd > /dev/null

  echo -e "${GREEN} Done. ${NC}"
  sleep 0.5 # delay for 0.5 seconds
  echo


############################
# Setting up SSH variables #
############################

echo -e "${GREEN} Setting up SSH variables...${NC}"

# Define the file path
FILEPATH="/etc/ssh/sshd_config"

# Enable challenge-response passwords
if ! sudo sed -i 's|KbdInteractiveAuthentication no|#KbdInteractiveAuthentication no|g' $FILEPATH; then
    echo -e "${RED} Failed to enable challenge-response passwords. Exiting.${NC}"
    exit 1
fi

# Changing Log level (default INFO)
if ! sudo sed -i 's|#LogLevel INFO|LogLevel VERBOSE|g' $FILEPATH; then
    echo -e "${RED} Failed to change log level. Exiting.${NC}"
    exit 1
fi

# Determines whether the root user can log in to the system remotely via SSH
if ! sudo sed -i 's|#PermitRootLogin prohibit-password|PermitRootLogin no|g' $FILEPATH; then
    echo -e "${RED} Failed to set root login permissions. Exiting.${NC}"
    exit 1
fi

# Enforce additional security restrictions
if ! sudo sed -i 's|#StrictModes yes|StrictModes yes|g' $FILEPATH; then
    echo -e "${RED} Failed to enforce security restrictions. Exiting.${NC}"
    exit 1
fi

# Limit number of authentication attempts to prevent brute-force attacks
if ! sudo sed -i 's|#MaxAuthTries 6|MaxAuthTries 3|g' $FILEPATH; then
    echo -e "${RED} Failed to limit authentication attempts. Exiting.${NC}"
    exit 1
fi

# Maximum number of Sessions
if ! sudo sed -i 's|#MaxSessions 10|MaxSessions 2|g' $FILEPATH; then
    echo -e "${RED} Failed to set maximum sessions. Exiting.${NC}"
    exit 1
fi

# Disable host-based authentication
if ! sudo sed -i 's|#IgnoreRhosts yes|IgnoreRhosts yes|g' $FILEPATH; then
    echo -e "${RED} Failed to disable host-based authentication. Exiting.${NC}"
    exit 1
fi

# Disable password authentication
if ! sudo sed -i 's|#PasswordAuthentication yes|PasswordAuthentication no|g' $FILEPATH; then
    echo -e "${RED} Failed to disable password authentication. Exiting.${NC}"
    exit 1
fi

# Ensure empty passwords are not allowed
if ! sudo sed -i 's|#PermitEmptyPasswords no|PermitEmptyPasswords no|g' $FILEPATH; then
    echo -e "${RED} Failed to ensure empty passwords are not allowed. Exiting.${NC}"
    exit 1
fi

# Test configuration for agent forwarding
if ! sudo sed -i 's|#AllowAgentForwarding yes|AllowAgentForwarding yes|g' $FILEPATH; then
    echo -e "${RED} Failed to configure SSH agent forwarding. Exiting.${NC}"
    exit 1
fi

# Use GSSAPIAuthentication
if ! sudo sed -i 's|#GSSAPIAuthentication no|GSSAPIAuthentication no|g' $FILEPATH; then
    echo -e "${RED} Failed to configure GSSAPIAuthentication. Exiting.${NC}"
    exit 1
fi

# Update SSH settings to use stronger encryption and key exchange algorithms
if ! (sudo sed -i '/# Ciphers and keying/a Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr' $FILEPATH \
    && sudo sed -i '/chacha20-poly1305/a KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256' $FILEPATH \
    && sudo sed -i '/curve25519-sha256/a Protocol 2' $FILEPATH); then
    echo -e "${RED} Failed to update SSH encryption and key exchange algorithms. Exiting.${NC}"
    exit 1
fi

echo -e "${GREEN} Done.${NC}"
sleep 0.5 # delay for 0.5 seconds
echo


################################################
# Enabling Keyboard-interactive authentication #
################################################

echo -e "${GREEN} Enabling Keyboard-interactive authentication ${NC}"

# Define the line to append
LINE="AuthenticationMethods keyboard-interactive"

# Append the line to the end of the file and check if the operation is successful
if echo "$LINE" | sudo tee -a /etc/ssh/sshd_config > /dev/null; then
    echo -e "${GREEN} Done.${NC}"
else
    echo -e "${RED} Failed to enable Keyboard-interactive authentication. Exiting.${NC}"
    exit 1
fi

sleep 0.5 # delay for 10.5 second
echo


#######################################################
# Enabling ChallengeResponseAuthentication explicitly #
#######################################################

echo -e "${GREEN} Enabling ChallengeResponseAuthentication ${NC}"

# Define the line to append
LINE="ChallengeResponseAuthentication yes"

# Append the line to the end of the file and check if the operation is successful
if echo "$LINE" | sudo tee -a /etc/ssh/sshd_config > /dev/null; then
    echo -e "${GREEN} Done.${NC}"
else
    echo -e "${RED} Failed to enable ChallengeResponseAuthentication. Exiting.${NC}"
    exit 1
fi

sleep 0.5 # delay for 0.5 second
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


#################################
# Changing the SSH default port #
#################################

# Set the initial SSH port number
current_ssh_port=22

# Prompt the user to change the SSH standard port
echo -e "${GREEN} Change SSH default port (22) to a non-standard port to reduce the risk of automated attacks. ${NC}"

echo
sleep 0.5 # delay for 0.5 second

while true; do
  echo -e "${GREEN} Do you want to change the SSH standard port?${NC} (yes/no) "
  echo
  read choice
  echo

  if [[ "$choice" =~ ^[yY][eE][sS]$ ]]; then
      # Generate a random number between 49152 and 65535 using shuf
      random_num=$(shuf -i 49152-65535 -n 1)
      current_ssh_port=$random_num

      # Define the file path
      FILEPATH="/etc/ssh/sshd_config"

      # Replace the standard SSH port with the random number in the sshd_config file
      if ! sudo sed -i "s/#Port 22/Port $random_num/g" $FILEPATH; then
          echo -e "${RED} Failed to update SSH configuration file. Exiting.${NC}"
          exit 1
      fi

      # Open the new SSH port in UFW and adjust rules
      if ! sudo ufw allow $random_num/tcp comment "SSH"; then
          echo -e "${RED} Failed to update UFW rules. Exiting.${NC}"
          exit 1
      fi

      # Automatically delete the default SSH port rule from UFW
      if ! yes | sudo ufw delete 1; then
          echo -e "${RED} Failed to delete UFW rule (1). Please check UFW rule numbers and adjust manually if necessary.${NC}"
      fi

      if ! yes | sudo ufw delete 2; then
          echo -e "${RED} Failed to delete UFW rule (2). Please check UFW rule numbers and adjust manually if necessary.${NC}"
      fi

      # Restart the SSH service
      if ! sudo systemctl restart sshd.service; then
          echo -e "${RED} Failed to restart SSH service. Check the system logs for errors.${NC}"
          exit 1
      fi

      echo
      echo -e "${GREEN} The new SSH port is:${NC} $random_num"

      break
  elif [[ "$choice" =~ ^[nN][oO]$ ]]; then
      echo -e "${GREEN} No changes were made to the SSH standard port. ${NC}"
      break
  else
      echo -e "${YELLOW} Invalid input. Please enter 'yes' or 'no'${NC}"
  fi
done

sleep 0.5 # delay for 0.5 second

echo
echo -e "${GREEN} Making Fail2Ban configuration reflect SSH port change.${NC}"
if ! sudo sed -i "s|port    = ssh|port    = $random_num|g" /etc/fail2ban/jail.local || ! sudo sed -i "s/port     = ssh/port     = $random_num/g" /etc/fail2ban/jail.local; then
    echo -e "${RED} Failed to update Fail2Ban configuration. Exiting.${NC}"
    exit 1
fi

echo
echo -e "${GREEN} SSH configuration and UFW rules updated successfully.${NC}"


################
# Disable IPv6 #
################

while true; do
    # Prompt the user for action
    echo
    echo -e "${GREEN} Do you want to disable IPv6?${NC} (yes/no) "
    echo
    read choice
    case $choice in
        y|Y|yes|YES)
            echo
            echo -e "${GREEN} Disabling IPv6...${NC}"
            
            # Temporarily disable IPv6
            if ! sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null \
                || ! sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null; then
                echo -e "${RED} Failed to temporarily disable IPv6. Exiting.${NC}"
                exit 1
            fi

            # Persistently disable IPv6
            if ! echo "net.ipv6.conf.all.disable_ipv6=1" | sudo tee -a /etc/sysctl.conf >/dev/null \
                || ! echo "net.ipv6.conf.default.disable_ipv6=1" | sudo tee -a /etc/sysctl.conf >/dev/null; then
                echo -e "${RED} Failed to persistently disable IPv6. Exiting.${NC}"
                exit 1
            fi
            break
            ;;
        n|N|no|NO)
            # No action taken, IPv6 remains enabled. No explicit success notification here either.
            break
            ;;
        *)
            echo -e "${YELLOW} Invalid input. Please enter${NC} 'yes' or 'no'"
            ;;
    esac
done

echo
sleep 0.5 # delay for 0.5 seconds


####################################################################################
# Generating an Ed25519 SSH key with a key derivation function rounds value of 200 #
####################################################################################

echo -e "${GREEN} Generating an Ed25519 SSH key ${NC}"
echo

# Generate the SSH key and check if the operation is successful
if ssh-keygen -t ed25519 -a 200 -N "" -f ~/.ssh/id_ed25519; then
    echo
    echo -e "${GREEN} Done.${NC}"
else
    echo -e "${RED} Failed to generate an Ed25519 SSH key. Exiting.${NC}"
    exit 1
fi

sleep 0.5 # delay for 0.5 seconds
echo


###################################################################
# Setting up Two-Factor Authentication using Google-Authenticator #
###################################################################

echo -e "${GREEN} Setting up Two-Factor Authentication using Google-Authenticator${NC}"
echo
echo -e "${GREEN} Use it to setup Google Authenticator app on your smartphone. Save scratch codes.${NC}"

echo

sleep 1 # delay for 1 seconds

# Execute the command and check if the operation is successful
if google-authenticator -d -f -t -r 3 -R 30 -W; then
    echo
    echo -e "${GREEN} Google Authenticator setup is complete.${NC}"
else
    echo -e "${RED} Failed to setup Google Authenticator. Exiting.${NC}"
    exit 1
fi

echo

# Explanation of options used:
#    -d: disallow reuse of the same token twice,
#    -f: forces the creation of a new secret key for the Google Authenticator,
#    -t: issue time-based rather than counter-based codes,
#    -r 3: limit the user to a maximum of three logins every 30 seconds,
#    -R 30: sets a rate limit for login attempts,
#    -W: display "warm-up" codes when first setting up Google Authenticator


######################
# Info before reboot #
######################

username=$(whoami)
ip_address=$(ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{ print $2}' | cut -d/ -f1)
# command that shows only first identified ip v4 address
#ip_address=$(ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{ print $2}' | cut -d/ -f1 | head -n 1)
# capturing the contents of the public key
PUB_KEY=$(cat ~/.ssh/id_ed25519.pub)
echo
echo -e "${GREEN} Everything is set. Your new Bastion Host | Jump Server is ready! ${NC}"
echo
echo
echo -ne "${GREEN} SSH Public key. For Template creation.${NC}"
echo
echo
echo " $PUB_KEY"
echo	
echo
echo -e "${GREEN} Please DO NOT forget to remember the SSH port number (if changed) ${NC}"

echo
echo -e "${GREEN} SSH port is ##  ${RED}$current_ssh_port ${NC} ${GREEN}## ${NC}"          #default port number (22) can be omitted
echo

echo -e "${GREEN} You can always use Proxmox VE VM Console to find the SSH port number in${NC} '/etc/ssh/sshd_config' ${GREEN}file ${NC}"
echo
echo
echo -e "${GREEN} SSH to this Server using the command: ${NC}"
echo
echo -e " ssh $username@$ip_address -p $current_ssh_port"
echo
echo -e "${GREEN} To jump to a remote host (from your local machine) use the command: ${NC}"
echo
echo -e " ssh -J $username@$ip_address:$current_ssh_port username@remote_host"
echo

sleep 0.5 # delay for 0.5 seconds


############################################
# Ask user to power restart or exit script #
############################################

while true; do
  echo -e "${GREEN} Restart the VM now${NC} (recommended) ${GREEN}or exit the script?${NC} (restart/exit):"
  echo
  read action

  case $action in
    restart)
      echo
      echo -e "${GREEN} This machine will restart... ${NC}"
      sleep 0.5 # delay for 0.5 seconds
      sudo apt clean && sudo apt autoremove && sudo reboot now
      break # Exit the loop after initiating power off
      ;;
    exit)
      echo
      echo -e "${RED} Exiting script. Remember to restart later!${NC}"
      exit 0
      ;;
    *)
      echo
      echo -e "${YELLOW} Invalid input. Please enter:${NC} 'restart' or 'exit'"
      echo
      ;;
  esac
done
