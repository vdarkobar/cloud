<p align="left">
  <a href="https://github.com/vdarkobar/cloud/tree/main?tab=readme-ov-file#self-hosted-homelab-cloud">back</a>
  <br>
</p> 
  
## Proxmox Virtual Environment
   
Cron expression to update Proxmox every month "At 00:00, on day 1 of the month":

```
crontab -e
```
```
0 0 1 * * apt update && apt dist-upgrade -y && reboot
```

Upgrade from 7 to 8

```
sed -i 's/bullseye/bookworm/g' /etc/apt/sources.list
```
```
apt update && apt dist-upgrade
```
```
pveversion
```
  
Enable PCIE passthrough, > PVE 8:
```
nano /etc/default/grub
```
for Intel System: 
```
GRUB_CMDLINE_LINUX_DEFAULT="quiet intel_iommu=on"
```
for AMD System: 
```
GRUB_CMDLINE_LINUX_DEFAULT="quiet amd_iommu=on"
```
```
update-grub
```
```
nano  /etc/modules
```
```
vfio
vfio_iommu_type1
vfio_pci
vfio_virqfd
```
```
update-initramfs -u -k all
```
```
reboot
```
  
Figure out the /dev/id-s for the disks. 
```
ls /dev/disk/by-id
```

Use *fdisk* command:
```
fdisk /dev/<disk_id>

Welcome to fdisk (util-linux 2.29.2).
Changes will remain in memory only, until you decide to write them.
Be careful before using the write command.

Command (m for help):		
```


  
Raw SSD passthrough to VM
For every SSD select new SCSI controler (-scsi1, -scsi2...), skip -scsi0 (boot disk):
```
qm set {vmid} -scsi1 /dev/disk/by-id/xxx
qm set {vmid} -scsi2 /dev/disk/by-id/xxx
```
Add an existing virtual disk to VM
```
qm rescan
```
```
qm set {vmid} --scsi0 {pool-name}:{image-name}
```
  
# ZFS
## Create ZFS Pool, add Cache
```
zpool create -f -o ashift=12 <pool_name> mirror /dev/disk/by-id/<disk_id> /dev/disk/by-id/<disk_id>
zpool add -f <pool_name> cache /dev/disk/by-id/<disk_id>
```
```  
zpool create -f -o ashift=12 main mirror /dev/disk/by-id/xxx /dev/disk/by-id/xxx

zpool add -f main mirror /dev/disk/by-id/xxx /dev/disk/by-id/xxx
zpool add -f main cache /dev/disk/by-id/xxx
```
```
zfs set compression=on <pool_name>
zfs set compression=lz4 <pool_name>
zpool get feature@lz4_compress <pool_name>
```
  
zpool
```
zpool status
zpool status -v
zpool list
zpool list -v
zpool iostat
zpool iostat -v
zpool create 
zpool create -f
zpool destroy
zpool add <pool_name> function <device_name>			#zpool add -f data_pool cache(log/spare) sdc(/dev/sdc)
zpool remove <pool_name> <device_name>				#zpool remove data_pool /dev/...
zpool offline <pool_name> <device_name>				#make device offline
zpool online <pool_name> <device_name>
```	
  
zfs
```
zfs list
zfs list -v
zfs get all <pool_name>						#zfs get all pool name | more, enter za dalje...
zfs parameter=off(on) <pool_name>				
zfs set compression=off <pool_name>				#for database set compression off !!!
zfs set compression=off <pool_name>/<filesystem_name>		#for database set compression off !!!
zfs get compressratio <pool_name>
zfs get compressratio <pool_name> | egrep -v '(@|1.00x)' 	#filter out datasets that don't see any benefit from compression and snapshots
zfs destroy <pool_name>
zfs destroy <pool_name>/<dataset_name>
```
  
Create new datasets under zfs and mount them to system:
```
zfs create <pool_name>/<datase_name> -o mountpoint=/mnt/<datase_name>
```
  
The snapshot entry is stored in the /etc/pve/qemu-server/<vmid>.conf file of your VM, you can delete the entry by hand:
  
Copy/make backup of net-config file:
```
cp /etc/network/interfaces /etc/network/interfaces.bak
```
  
Change network settings without system restart:
```
cp /etc/network/interfaces.new /etc/network/interfaces
systemctl restart networking.service
```
  
Show net config:
```
ip a
```
  
## UPS
```	
apt-get install -y apcupsd apcupsd-cgi
cp /etc/default/apcupsd /etc/default/apcupsd.bak
nano /etc/default/apcupsd
```
Change:
```
ISCONFIGURED=yes					#save and exit
```
```
tail -f /var/log/messages				#check
```
To find device ID:
```
lsusb
lsusb -v -d device ID					#or> lsusb -v -d device ID | less
```
Config:
```
cp /etc/apcupsd/apcupsd.conf /etc/apcupsd/apcupsd.conf.bak
nano /etc/apcupsd/apcupsd.conf
```
Change to:
```
	UPSNAME name...
	UPSCABLE usb
	UPSTYPE usb
	DEVICE 
	POLLTIME 60
```
Change BATTERYLEVEL form 5 to 25, so the system have enough time to shutdown.
  
Start
```
apcupsd start
```
or
```	
/etc/init.d/apcupsd start					#/etc/init.d/apcupsd stop, /etc/init.d/apcupsd restart
```
```
apcaccess status
```
In order to run apctest, one must first stop apcupsd via a terminal:
```		
systemctl stop apcupsd
apctest
systemctl start apcupsd
```
misc
```
ps aux | grep apcupsd
netstat -tulpn | grep apcupsd
tail -f /var/log/apcupsd.events
```		
  
# Windows Guest on Proxmox
  
<p align="center">
  <b>Download:</b><br>
<a href="https://github.com/vdarkobar/cloud/blob/main/misc/windows.md">Windows</a> |
<a href="https://docs.fedoraproject.org/en-US/quick-docs/creating-windows-virtual-machines-using-virtio-drivers/index.html#virtio-win-direct-downloads">VirtIO drivers</a> >
<a href="https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso">Stable</a> |
<a href="https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/latest-virtio/virtio-win.iso">Latest</a>

  <br><br>
</p>

VM
```
- virtual hard disk > 			"SCSI"  Set  as  for best performance  and tick
- controller > 				"VirtIO SCSI"
- cache option > 			"Write Through" (explanation: https://medium.com/@carll/installing-server-2016-2019-core-gui-less-with-proxmox-649ba8d634db)

- !!! for TRIM option tick !!! > 	"Discard" (to optimally use disk space)
```
  
Pre-installation
```
	-NetKVM — the VirtIO Ethernet driver
	-viostor — the VirtIO block storage driver
	-vioscsi — the VirtIO SCSI driver
	-qxldod — QXL graphics driver (if installing Windows 7 or earlier, choose qxl instead)
```
Post-installation
```
	-Balloon — VirtIO memory balloon driver (optional, but recommended unless your server has plenty of RAM)
	#Copy folder> D:\Balloon\w10\amd64 to C:\Program Files and rename it to: Balloon
	#Open CMD as Administrator, CD to C:\Program Files\Balloon> and run command: blnsvr.exe -i
	-guest-agent
```
  

CATEGORY / OPTION / VALUE
```
OS			Guest OS		Microsoft Windows (10/Server)
			      CD image		Your downloaded ISO

System			Graphics card		Default
			      SCSI Controller	VirtIO SCSI
			      Qemu Agent	Enabled

Hard Disk		Bus/Device		VirtIO Block (0)
			      Disk Size		>50GB ideally
			      Cache		Write Through

CPU			Sockets			1 (adjust to your needs)
			      Cores		4 (adjust to your needs)
			      Type		host

Memory			Memory			8192 (adjust to your liking)
Network			Model			VirtIO (paravirtualized)
```
  
<!--- Commented out
>>> After PVE version 6.2-12

# run > lspci -nn to identify device ID's, in my case "1000:0097":

01:00.0 Serial Attached SCSI controller [0107]: LSI Logic / Symbios Logic SAS3008 PCI-Express Fusion-MPT SAS-3 [1000:0097] (rev 02)
02:00.0 Serial Attached SCSI controller [0107]: LSI Logic / Symbios Logic SAS3008 PCI-Express Fusion-MPT SAS-3 [1000:0097] (rev 02)

# create/edit file, add: 
nano /etc/modprobe.d/passthrough.conf

blacklist mpt3sas
options vfio-pci ids=1000:0097

# run > lspci -nnk to identify device Kernel modules, in my case "mpt3sas":

01:00.0 Serial Attached SCSI controller [0107]: LSI Logic / Symbios Logic SAS3008 PCI-Express Fusion-MPT SAS-3 [1000:0097] (rev 02)
        Subsystem: Super Micro Computer Inc SAS3008 PCI-Express Fusion-MPT SAS-3 (AOC-S3008L-L8e) [15d9:0808]
        Kernel driver in use: vfio-pci
        Kernel modules: mpt3sas
02:00.0 Serial Attached SCSI controller [0107]: LSI Logic / Symbios Logic SAS3008 PCI-Express Fusion-MPT SAS-3 [1000:0097] (rev 02)
        Subsystem: Dell HBA330 Adapter [1028:1f45]
        Kernel driver in use: vfio-pci
        Kernel modules: mpt3sas

# create/edit file, add:  
nano /etc/modprobe.d/pve-blacklist.conf

blacklist nvidiafb (# was there already)
blacklist mpt3sas

# create/edit file, add:
# or use command > echo "options vfio_iommu_type1 allow_unsafe_interrupts=1" > /etc/modprobe.d/iommu_unsafe_interrupts.conf
nano /etc/modprobe.d/iommu_unsafe_interrupts.conf

options vfio_iommu_type1 allow_unsafe_interrupts=1

# and run > update-initramfs -u -k all

Reboot

# also, edited file to look like this:
nano /etc/default/grub.d/init-select.cfg

GRUB_CMDLINE_LINUX_DEFAULT="${GRUB_CMDLINE_LINUX_DEFAULT} intel_iommu=on"

run > dmesg | grep -e DMAR -e IOMMU (# returns > ... 0.541356] DMAR: IOMMU enabled)
run > find /sys/kernel/iommu_groups/ -type l (# returns > /sys/kernel/iommu_groups/17/devices/0000:00:04.0 ...)
--->
