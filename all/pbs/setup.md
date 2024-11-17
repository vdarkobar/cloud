<p align="left">
  <a href="https://github.com/vdarkobar/cloud/tree/main?tab=readme-ov-file#self-hosted-homelab-cloud">back</a>
  <br>
</p> 
  
## Proxmox Backup Server
  
Install the qemu-guest-agent
```
apt install qemu-guest-agent
```  
  
Restore the Datastore to another Server (PBS)

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

