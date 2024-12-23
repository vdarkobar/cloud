<p align="left">
  <a href="https://github.com/vdarkobar/cloud/tree/main?tab=readme-ov-file#self-hosted-homelab-cloud">back</a>
  <br>
</p> 
  
## Cloudflare
  
Login to <a href="https://dash.cloudflare.com/">Cloudflare</a> and point your root domain (example.com) to your WAN IP using an A record.  
```
    A | example.com | YOUR WAN IP
```
<p align="center">
  <img src="https://github.com/vdarkobar/cloud/blob/main/misc/A-record.webp">
</p>
  
Add individual *subdomains*, for all services, pointing to your root domain (@ for the host).  
```
    CNAME | * | @ (or example.com)
```
<p align="center">
  <img src="https://github.com/vdarkobar/cloud/blob/main/misc/sub-domain.webp">
</p>
  
Add for non-WWW to WWW redirect.  
```
    CNAME | www | YOUR WAN IP
```
<p align="center">
  <img src="https://github.com/vdarkobar/cloud/blob/main/misc/www.webp">
</p>
  
### *Website settings*:
<pre>
SSL/TLS Mode - Full (strict)  

Edge Certificates:  
  Always Use HTTPS: ON  
  HTTP Strict Transport Security (HSTS): Enable
  - Max Age Header (max-age) 6 months
  - Apply HSTS policy to subdomains: ON
  - Preload: OFF(?)
  - No-Sniff Header: ON
  Minimum TLS Version: 1.2  
  Opportunistic Encryption: ON  
  TLS 1.3: ON  
  Automatic HTTPS Rewrites: ON  
  Certificate Transparency Monitoring: ON   
  
Security:
  Bot Fight Mode: ON 
  Security Level: Medium  
  Challenge Passage: 30 Minutes  
  Browser Integrity Check: ON  
</pre>

<br>

### *<a href="https://dash.cloudflare.com/profile/api-tokens">CloudFlare Global API Key</a>*

<br>

### When behind *dynamic IP address* (set by ISP)

1. to link your public `IP` (dynamic) to domain name: `example.com`   
```
    CNAME | example.com | YOUR dynamic DNS
```
example:
```
    CNAME | example.com | <your_subdomain>.duckdns.org>
```
2. to add subdomain for some service:
```
    CNAME | <service subdomain> | example.com
```

