<p align="left">
  <a href="https://github.com/vdarkobar/cloud/tree/main?tab=readme-ov-file#self-hosted-homelab-cloud">back</a>
  <br>
</p> 
  
### Nginx Proxy Manager
*Reverse Proxy for all of your Services!*  

<p align="center">
  <img src="https://github.com/vdarkobar/cloud/blob/main/misc/reverse-proxy.png">
</p>
  
---  

<p align="center">
<i>Enable Port forwarding (80, 443) from your Router/Firewall to your NPM instance.</i>
</p>  
  
---  

### Default Administrator User
```
Email:    admin@example.com
Password: changeme
```
  
### Create <a href="https://dash.cloudflare.com/profile/api-tokens">CloudFlare API Token</a>.  

Used for *DNS Challenge* to create *Wildcard Certificates* for your entire Domain (*unlimited Subdomains*).  
  
> CloudFlare: Profile > API Tokens > Create Token > Edit zone DNS - Use Template  
  
> Create Token: change the name (use Domain name with the star in front: *.example.com)  
  
> Permissions: Zone > DNS > Edit
  
> Zone Resources: Include > Specific Zone > example.com
  
> Client IP Address Filtering: *skip or set up if you have fixed ip address
  
> TTL: skip or define how long this token will stay active
  
> Continue to summary > Create Token
  
### Copy *Token* and paste it to:
  
> Nginx Proxy Manager > SSL Certificates > Add SSL Certificate > Let's Encrypt > Domain Names (enter: *.example.com example.com) 

> Enable: Use a DNS Challenge > CloudFlare > Credentials File Content * (paste Token after = sign) > Save  
  
