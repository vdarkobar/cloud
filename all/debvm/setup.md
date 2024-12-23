<p align="left">
  <a href="https://github.com/vdarkobar/cloud/tree/main?tab=readme-ov-file#self-hosted-homelab-cloud">back</a>  
  <br>
</p> 
  
### Manually ceate Debian Server Cloud-Init Template to use with Proxmox 
  
> *Create Proxmox VM: (2CPU/2GBRAM/8GBHDD) using <a href="https://www.debian.org/">Debian</a>.*  
> *Do not set root password during installation, this way created user will gain sudo privileges.*   
> *Add SSH Server during installation.*  
> *For ProxMox VM disk Resize option to work, create VM without SWAP Partition during install process (SWAP File)*
```bash
Partition disks > Manual > Continue
Select disk > SCSI3 QEMU HARDDISK > Continue
Create new empty Partition > Yes > Continue
New Partition Size > Continue
Primary > Continue
Bootable Flag > On > Done setting up the Partition > Continue
Finish partitioning and write changes to the disk > Continue
Return to the partitioning menu > No > Continue
Write changes to the disk > Yes > Continue
```
> *(VM > Hardware > Hard Disk > Disk Action > Resize)*  
  
### *Follow <a href="https://github.com/vdarkobar/cloud/blob/main/all/debvm/step-by-step.md">these</a> steps to configure Debian Server Template*
