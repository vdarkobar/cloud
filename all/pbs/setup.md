<p align="left">
  <a href="https://github.com/vdarkobar/cloud/tree/main?tab=readme-ov-file#self-hosted-homelab-cloud">back</a>
  <br>
</p> 
  
## Proxmox Backup Server
  
Install the qemu-guest-agent
```
apt install qemu-guest-agent
```  
  
### Restore the Datastore to another PBS Server (ZFS Pool)

Create new PBS VM, attach the disk(s) and import the ZPF Pool (Pool name = Datastore name from the old PBS):
```
zpool import -f <pool name>
```  
  
Check the pool using `zfs list` command (it will give you `NAME` and `MOUNTPOINT`):
```
zfs list
```  
  
Create a `datastore.cfg` file: 
```
nano /etc/proxmox-backup/datastore.cfg
```
  
with the provided (`zfs list`) `NAME` and `MOUNTPOINT`:
```
datastore: <name>			<---NAME
    path /path/to/your/backups		<---MOUNTPOINT
```

Add Datastore to Proxmox VE ( `Datacenter > Storage > Add` ).  
 
<br>

### Tandberg RDX QuikStor

check if the device is detected:
```
lsblk
```

Confirm that the device is recognized as a USB storage device:
```
dmesg | grep usb
```

check the filesystem of the cartridge using:
```
fdisk -l /dev/sdX
```

if you want to clean it, you can format it:
```
mkfs.ext4 /dev/sdX
```

create a mount point for the RDX cartridge:
```
mkdir -p /mnt/rdx
```

Mount the device:
```
mount /dev/sdX /mnt/rdx
```

Verify the mount:
```
df -h
```

initialize the datastore:
```
proxmox-backup-manager datastore create RDX-Backup /mnt/rdx
```

Confirm that the datastore is correctly configured:
```
proxmox-backup-manager datastore list
```

ensure the RDX device mounts automatically on reboot or cartridge change:
Get the UUID of the RDX cartridge:
```
blkid /dev/sdX
```

Note the UUID value.
Add the UUID to /etc/fstab:
```
nano /etc/fstab
```

Add a line like: `UUID=<your-rdx-uuid> /mnt/rdx ext4 defaults 0 2`

example: `UUID=6a247998-6724-4214-8004-265004e5d50d /mnt/rdx ext4 defaults 0 2`

Test the configuration:
```
umount /mnt/rdx
mount -a
```

datastore configuration file:
```
nano /etc/proxmox-backup/datastore.cfg
```

RDX device:
```
datastore: RDX-Backup
    path /mnt/rdx
```

Restart the PBS service to apply the changes:
```
systemctl restart proxmox-backup
```

Check if the datastore is listed:
```
proxmox-backup-manager datastore list
```

logs:
```
journalctl -u proxmox-backup -f
```

### To import an RDX-based datastore to a different Proxmox Backup Server (PBS), follow these steps:

Prepare the Target Server
Ensure the target PBS server is ready to receive the datastore:

Connect the RDX cartridge to the target PBS server and ensure the device is detected:
```
lsblk
```
```
dmesg | grep usb
```

Identify the Device, Check the filesystem and UUID of the RDX cartridge:
```
fdisk -l /dev/sdX
blkid /dev/sdX
```

Create a mount point for the RDX device on the target server:
```
mkdir -p /mnt/rdx
```

Mount the RDX Cartridge
```
mount /dev/sdX /mnt/rdx
```

Verify the mount:
```
df -h
```

Add the datastore configuration to the target PBS:
```
proxmox-backup-manager datastore create RDX-Backup /mnt/rdx
```

Confirm the configuration:
```
proxmox-backup-manager datastore list
```

Ensure Auto-Mount on Reboot, Add the UUID of the cartridge to /etc/fstab:
```
blkid /dev/sdX
nano /etc/fstab
```

Add a line similar to the one on the original server: `UUID=<your-rdx-uuid> /mnt/rdx ext4 defaults 0 2`

Test the configuration:
```
umount /mnt/rdx
mount -a
```

Restart the PBS service on the target server to recognize the new datastore:
```
systemctl restart proxmox-backup
```
Ensure the datastore is listed and functional:
```
proxmox-backup-manager datastore list
```

Check logs for any errors:
```
journalctl -u proxmox-backup -f
```

Import Existing Backups
If the datastore contains existing backups, 
they should automatically be available after the datastore is mounted and configured. 
Verify the backups using:
```
proxmox-backup-client list --repository RDX-Backup
```

You can then configure backup jobs to use this datastore or restore backups as needed.
By following these steps, you can successfully import the RDX-based datastore to a different Proxmox Backup Server.
