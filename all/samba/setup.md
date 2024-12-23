<p align="left">
  <a href="https://github.com/vdarkobar/cloud/tree/main?tab=readme-ov-file#self-hosted-homelab-cloud">back</a>
  <br>
</p> 
  
### Samba  
  
Install Samba Packages
```
sudo apt install -y samba smbclient cifs-utils
```
```
sudo systemctl status smbd
```
```
smbstatus --version
```

Backup configuration file
```
sudo cp /etc/samba/smb.conf /etc/samba/smb.conf.bak
```

Samba configuration file
```
sudo nano /etc/samba/smb.conf
```

Verify the Samba configuration
```
sudo testparm
```

Restart the Samba service
```
sudo systemctl restart smbd nmbd
```

Create Shared Samba Directories
```
sudo mkdir /public && sudo mkdir /private
```

Create Samba share (smbshare) user group
```
sudo groupadd smbshare
```

Add the necessary group permissions for the private share.
```
sudo chgrp -R smbshare /private && sudo chgrp -R smbshare /public   # root:smbshare
# sudo chown -R username:group directory
```

Set the right directory permissions.
```
sudo chmod 2770 /private && sudo chmod 2775 /public
```

Create a no login local user to access the private share
```
sudo useradd -M -s /sbin/nologin sambauser
```

Add the user to the Samba share group created above.
```
sudo usermod -aG smbshare sambauser
```

Create an SMB password for the user  
Even if your system user has a password, Samba requires its own password to be set for share access.
```
sudo smbpasswd -a sambauser
```

Enable the created account:
```
sudo smbpasswd -e sambauser
```

List all users in a group
```
grep '^group_name_here:' /etc/group
```
```
getent group group_name_here
```

Check (list) users on the system
```
awk -F: '{ print $1}' /etc/passwd
```
```
cut -d: -f1 /etc/passwd
```

Allow Samba traffic (Ports: 137,138/udp, 139,445/tcp)
```
sudo ufw allow Samba
```
```
sudo ufw app info Samba
```

Or, allow remote access from the specified IP range to Samba (more secure)
```
sudo ufw allow from 192.168.30.0/24 to any app Samba
```

Create demo files in the Samba shares, try accessing the share from your local machine
```
sudo mkdir /private/demo-private /public/demo-public && \
sudo touch /private/demo1.txt /public/demo2.txt
```

Test access to the share locally
```
smbclient '\\localhost\private' -U sambauser
```
```
smbclient '\\localhost\public'
```

List what services are available on a Samba server
```
smbclient -L //server-ip/ -U sambauser
```

To set up a Linux client, you will need Samba packages:
```
sudo apt install samba-client cifs-utils
```

Once installed, navigate to File manager->Other locations and add your share using the syntax below.
```
smb://servername/Share_name
```

### `smb.conf` file
```

# Global parameters
[global]
    workgroup = WORKGROUP
    server string = Samba Server
    server role = standalone server

    # Consistent logging - consider a higher max log size (%m.log)
    log file = /var/log/samba/log.%m
    max log size = 5000
    logging = file
    
    panic action = /usr/share/samba/panic-action %d
    obey pam restrictions = Yes
    pam password change = Yes
    unix password sync = Yes
    passwd program = /usr/bin/passwd %u
    passwd chat = *Enter\snew\s*\spassword:* %n\n *Retype\snew\s*\spassword:* %n\n *password\supdated\ssuccessfully* .
    map to guest = Bad User

    # Security Enhancements
    smb encrypt = mandatory
    client min protocol = SMB3
    server min protocol = SMB3
    idmap config * : backend = tdb
    usershare allow guests = No
    guest account = nobody  
    invalid users = root

    # VFS Audit logging (adjust paths/settings as needed)
    vfs objects = full_audit
    full_audit:prefix = %u|%I|%m|%S
    full_audit:success = mkdir rmdir open read write 
    full_audit:failure = none
    full_audit:priority = NOTICE

    # Recycle Bin Configuration 
    vfs objects = recycle
    recycle:touch = yes
    recycle:keeptree = yes
    recycle:versions = yes
    recycle:exclude_dir = tmp quarantine

# Share Definitions
[public]
    comment = Public Folder for Limited Guest Access
    path = /public
    browseable = Yes
    writable = No
    guest ok = Yes 

[private]
    comment = Private Folder
    path = /private
    # Valid user, in this case, is a group smbshare, add users to group to allow access
    valid users = @SMB_GROUP_HERE
    guest ok = No
    writable = Yes 
    read only = No
    # Security
    force create mode = 0770
    force directory mode = 0770
    inherit permissions = Yes
```
