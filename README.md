# *Self-hosted Home(lab) Cloud*

<p align="center">
  <img src="https://github.com/vdarkobar/cloud/blob/main/misc/infrastructure_small.webp">
</p>

<br>

<p align="center">
  <i>Add domain name to <a href="https://github.com/vdarkobar/cloud/blob/main/all/cloudflare/setup.md">Cloudflare</a>. 
  Install and configure <a href="https://github.com/vdarkobar/cloud/blob/main/all/pve/setup.md">Proxmox Virtual Environment</a> and 
  <a href="https://github.com/vdarkobar/cloud/blob/main/all/pbs/setup.md">Proxmx Backup Server</a>.</i>
  <br><br>
</p> 
  
<p align="center">
<i>Run script(s) inside a VM or LXC</i>
</p> 

</br>

### 1. *Debian VM <a href="https://github.com/vdarkobar/cloud/blob/main/all/debvm/setup.md"> * </a>*:
```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/vdarkobar/cloud/main/setup1.sh)"
```
### 2. *Debian LXC <a href="https://github.com/vdarkobar/cloud/blob/main/all/debct/setup.md"> * </a>*:
```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/vdarkobar/cloud/main/setup2.sh)"
```

</br>

### 3. *Bastion/Jump <a href="https://github.com/vdarkobar/cloud/blob/main/all/jump/setup.md"> * </a>*:
```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/vdarkobar/cloud/main/setup3.sh)"
```

</br>

### 4. *Unbound (opt. Pi-Hole) <a href="https://github.com/vdarkobar/cloud/blob/main/all/unbound/setup.md"> * </a>*:
```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/vdarkobar/cloud/main/setup4.sh)"
```

### 5. *Samba file server <a href="https://github.com/vdarkobar/cloud/blob/main/all/samba/setup.md"> * </a>*:
```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/vdarkobar/cloud/main/setup5.sh)"
```

### 6. *Nginx Proxy Manager (Docker) <a href="https://github.com/vdarkobar/cloud/blob/main/all/npm-d/setup.md"> * </a>*:
```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/vdarkobar/cloud/main/setup6.sh)"
```

### 7. *Nextcloud <a href="https://github.com/vdarkobar/cloud/blob/main/all/nc/setup.md"> * </a>*:
```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/vdarkobar/cloud/main/setup7.sh)"
```

### 8. *Nextcloud (Docker) <a href="https://github.com/vdarkobar/cloud/blob/main/all/nc-d/setup.md"> * </a>*:
```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/vdarkobar/cloud/main/setup8.sh)"
```

### 9. *Vaultwarden (Docker) <a href="https://github.com/vdarkobar/cloud/blob/main/all/vault-d/setup.md"> * </a>*:
```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/vdarkobar/cloud/main/setup9.sh)"
```


