# *Self-hosted Home(Lab) Cloud*

<p align="center">
  <img src="https://github.com/vdarkobar/cloud/blob/main/misc/infrastructure_small.webp">
</p>

<br>

<p align="center">
  Add domain name to <a href="https://github.com/vdarkobar/WordPress#wordpress">Cloudflare</a>. 
  Install and configure <a href="https://github.com/vdarkobar/NextCloud#nextcloud">ProxmoxVE</a> and 
  <a href="https://github.com/vdarkobar/Bitwarden#bitwarden">Proxmx Backup Server</a>
  <br><br>
</p> 

</br>

### 1. *Debian VM <a href="https://www.debian.org/index.html"> * </a>*:
```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/vdarkobar/cloud/main/setup1.sh)"
```
### 2. *Debian LXC <a href="https://www.debian.org/index.html"> * </a>*:
```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/vdarkobar/cloud/main/setup2.sh)"
```

</br>

### 3. *Bastion/Jump <a href="https://www.debian.org/index.html"> * </a>*:
```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/vdarkobar/cloud/main/setup3.sh)"
```

### 4. *Unbound (opt. Pi-Hole)  <a href="https://www.debian.org/index.html"> * </a>*:
```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/vdarkobar/cloud/main/setup4.sh)"
```

### 5. *Samba file server <a href="https://www.debian.org/index.html"> * </a>*:
```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/vdarkobar/cloud/main/setup5.sh)"
```

### 6. *Nginx Proxy Manager (Docker) <a href="https://www.debian.org/index.html"> * </a>*:
```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/vdarkobar/cloud/main/setup6.sh)"
```

### 7. *Nextcloud <a href="https://www.debian.org/index.html"> * </a>*:
```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/vdarkobar/cloud/refs/heads/main/all/debvm/setup.sh)"
```

### 8. *Nextcloud (Docker) <a href="https://www.debian.org/index.html"> * </a>*:
```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/vdarkobar/cloud/refs/heads/main/all/debvm/setup.sh)"
```

### 9. *Vaultwarden (Docker) <a href="https://www.debian.org/index.html"> * </a>*:
```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/vdarkobar/cloud/refs/heads/main/all/debvm/setup.sh)"
```







