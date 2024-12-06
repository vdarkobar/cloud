<p align="left">
  <a href="https://github.com/vdarkobar/cloud/tree/main?tab=readme-ov-file#self-hosted-homelab-cloud">back</a>
  <br>
</p> 
  
# Vaultwarden
    
Login to <a href="https://dash.cloudflare.com/">CloudFlare</a> and add: *Subdomain* for *Vaultwarden*, pointing to your *root Domain*.
  
> CNAME | subdomain | @ (or example.com)
  
example:
  
> CNAME | pass | @ (or example.com)
  
  
#### *Decide what you will use for*:
  
> Domain name of your website, Vaultwarden Subdomain, Port Number and Time Zone.  
  
#### Command will add *ADMIN TOKEN* to *.env* file, used to log in at:
```
https://subdomain.example.com/admin
```
  
### Log:
```bash
sudo docker compose logs vaultwarden
sudo docker logs -tf --tail="50" vaultwarden
```
  
#### Vaultwarden: <i><a href="https://github.com/dani-garcia/vaultwarden/wiki">Features</a></i>  
> *Enable Websockets Support.*  
> *Change: SIGNUPS_ALLOWED=true, to false after first login and rebuild containers.*  

to continue setup > your reverse proxy ...
