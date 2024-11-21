<p align="left">
  <a href="https://github.com/vdarkobar/cloud/tree/main?tab=readme-ov-file#self-hosted-homelab-cloud">back</a>
  <br>
</p> 
  
### Unbound and Pi-Hole
  
### Pi-Hole  
    
Prepare UFW  
```bash
      sudo ufw allow 80/tcp comment 'Pi-Hole' && \
      sudo ufw allow 53/tcp comment 'Pi-Hole' && \
      sudo ufw allow 53/udp comment 'Pi-Hole' && \
      sudo ufw allow 67/tcp comment 'Pi-Hole' && \
      sudo ufw allow 67/udp comment 'Pi-Hole' && \
      sudo ufw allow 5335/tcp comment 'Pi-Hole/Unbound' && \
      sudo ufw allow 5335/udp comment 'Pi-Hole/Unbound' && \
      sudo ufw allow 546:547/udp comment 'Pi-Hole IPv6'
```

Pi-Hole install  
```bash
sudo apt install curl -y && \
curl -sSL https://install.pi-hole.net | bash
```

Pi-hole Dashboard Password  
```bash
pihole -a -p
```
  
Update Pi-Hole  
```bash
pihole -up
```

Pi-hole Dashboard  
```bash
http://ip/admin
```
  
## Unbound  
  
Check package version (Unbound 1.18.0 (Current version))  
```bash
apt search unbound
```
```bash
sudo apt install -y unbound && \
sudo systemctl is-enabled unbound && \
sudo systemctl status unbound
```

Check installed package version  
```bash
sudo apt info unbound
```

Download the current root hints  
```bash
wget https://www.internic.net/domain/named.root -qO- | sudo tee /var/lib/unbound/root.hints
```

Reduce EDNS reassembly buffer size  
```bash
sudo nano /etc/dnsmasq.d/99-edns.conf
```
```bash
# add:  
edns-packet-max=1232
```
  
### Log  
  
Level 0 means no verbosity, only errors  
Level 1 gives operational information  
Level 2 gives  detailed operational  information  
Level 3 gives query-level information  
Level 4 gives  algorithm-level  information  
Level 5 logs client identification for cache misses  
  
Create log directory/file (If no logfile is specified, syslog is used)  
```bash
sudo mkdir -p /var/log/unbound && \
sudo touch /var/log/unbound/unbound.log && \
sudo chown unbound /var/log/unbound/unbound.log
```

Edit and append to the end (before the last  '}'  )  
```bash
sudo nano /etc/apparmor.d/usr.sbin.unbound
```
```bash
# add:  
/var/log/unbound/unbound.log rw,
```
  
Reload AppArmor using  
```bash
sudo apparmor_parser -r /etc/apparmor.d/usr.sbin.unbound && \
sudo service unbound restart
```

Setup cryptographic SSL keys necessary for the control option  
```bash
sudo unbound-control-setup
```

Configure unbound  
```bash
sudo nano /etc/unbound/unbound.conf.d/pi-hole.conf
```
  
### add:  
  
```bash
# Unbound configuration file for Debian.
#
# See the unbound.conf(5) man page.
#
# See /usr/share/doc/unbound/examples/unbound.conf for a commented
# reference config file.
#
# The following line includes additional configuration files from the
# /etc/unbound/unbound.conf.d directory.
include-toplevel: "/etc/unbound/unbound.conf.d/*.conf"

# Authoritative, validating, recursive caching DNS with DNS-Over-TLS support
server:

    # Limit permissions 
    username: "unbound"
    # Working directory
    directory: "/etc/unbound"
    # Chain of Trust
    tls-cert-bundle: /etc/ssl/certs/ca-certificates.crt

# Send minimal amount of information to upstream servers to enhance privacy
    qname-minimisation: yes

# Centralized logging
    use-syslog: yes
    # Increase to get more logging.
    verbosity: 2
    # For every user query that fails a line is printed
    val-log-level: 2
    # Logging of DNS queries
    log-queries: yes


# Root hints
    root-hints: /usr/share/dns/root.hints
    harden-dnssec-stripped: yes


# Listen on all interfaces, answer queries from the local subnet (access-control:).
    interface: 0.0.0.0
    interface: ::0

    do-ip4: yes
    do-ip6: yes
    do-udp: yes
    do-tcp: yes

    # Ports
    port: 53
    tls-port: 853

    # Use TCP connections for all upstream communications
    tcp-upstream: yes


# perform prefetching of almost expired DNS cache entries.
    prefetch: yes


# Enable DNS Cache
    cache-max-ttl: 14400
    cache-min-ttl: 1200


# Unbound Privacy and Security
    aggressive-nsec: yes
    hide-identity: yes
    hide-version: yes
    use-caps-for-id: yes


# Define Private Network and Access Control Lists (ACLs)
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: 172.16.0.0/12
    private-address: 10.0.0.0/8
    private-address: fd00::/8
    private-address: fe80::/10

    # Control which clients are allowed to make (recursive) queries
    access-control: 127.0.0.1/32 allow_snoop
    access-control: ::1 allow_snoop
    access-control: 127.0.0.0/8 allow
    access-control: LOCAL_SUBNET_ACCESS allow

    # Setup Local Domain
    private-domain: "DOMAIN_NAME_LOCAL"
    domain-insecure: "DOMAIN_NAME_LOCAL"
    local-zone: "DOMAIN_NAME_LOCAL." static

    # A Records Local
    local-data: "HOST_NAME_LOCAL.DOMAIN_NAME_LOCAL. IN A IP_LOCAL"

    # Reverse Lookups Local
    local-data-ptr: "IP_LOCAL HOST_NAME_LOCAL.DOMAIN_NAME_LOCAL"


   # Blocking Ad Server domains. Google's AdSense, DoubleClick and Yahoo
   # account for a 70 percent share of all advertising traffic. Block them.
   # Not guarantied use browser extensions like uBlock Origin, Adblock Plus,
   # or network-wide ad blockers e.g. Pi-hole
   local-zone: "doubleclick.net" redirect
   local-data: "doubleclick.net A 127.0.0.1"
   local-zone: "googlesyndication.com" redirect
   local-data: "googlesyndication.com A 127.0.0.1"
   local-zone: "googleadservices.com" redirect
   local-data: "googleadservices.com A 127.0.0.1"
   local-zone: "google-analytics.com" redirect
   local-data: "google-analytics.com A 127.0.0.1"
   local-zone: "ads.youtube.com" redirect
   local-data: "ads.youtube.com A 127.0.0.1"
   local-zone: "adserver.yahoo.com" redirect
   local-data: "adserver.yahoo.com A 127.0.0.1"
   local-zone: "ask.com" redirect
   local-data: "ask.com A 127.0.0.1"


# Unbound Performance Tuning and Tweak
    num-threads: 4
    msg-cache-slabs: 8
    rrset-cache-slabs: 8
    infra-cache-slabs: 8
    key-cache-slabs: 8
    rrset-cache-size: 256m
    msg-cache-size: 128m
    so-rcvbuf: 8m


# Use DNS over TLS
forward-zone:
    name: "."
    forward-tls-upstream: yes
    # Quad9 DNS
    forward-addr: 9.9.9.9@853#dns.quad9.net
    forward-addr: 149.112.112.112@853#dns.quad9.net
    forward-addr: 2620:fe::11@853#dns.quad9.net
    forward-addr: 2620:fe::fe:11@853#dns.quad9.net 
    # Quad9 DNS (Malware Blocking + Privacy) slower
 #   forward-addr: 9.9.9.11@853#dns11.quad9.net
 #   forward-addr: 149.112.112.11@853#dns11.quad9.net
 #   forward-addr: 2620:fe::11@853#dns11.quad9.net
 #   forward-addr: 2620:fe::fe:11@853#dns11.quad9.net

    # Cloudflare DNS
    forward-addr: 1.1.1.1@853#cloudflare-dns.com
    forward-addr: 1.0.0.1@853#cloudflare-dns.com
    forward-addr: 2606:4700:4700::1111@853#cloudflare-dns.com
    forward-addr: 2606:4700:4700::1001@853#cloudflare-dns.com
    # Cloudflare DNS (Malware Blocking) slower
 #   forward-addr: 1.1.1.2@853#cloudflare-dns.com
 #   forward-addr: 2606:4700:4700::1112@853#cloudflare-dns.com
 #   forward-addr: 1.0.0.2@853#cloudflare-dns.com
 #   forward-addr: 2606:4700:4700::1002@853#cloudflare-dns.com

    # Google
#    forward-addr: 8.8.8.8@853#dns.google
#    forward-addr: 8.8.4.4@853#dns.google
#    forward-addr: 2001:4860:4860::8888@853#dns.google
#    forward-addr: 2001:4860:4860::8844@853#dns.google
```
  
```bash
sudo unbound-checkconf
```
```bash
sudo systemctl restart unbound
```
  <br>
  <br>
Finally, configure Pi-hole to use your recursive DNS server by specifying ```127.0.0.1#5335``` as the Custom DNS (IPv4).
  <br>
  <br>

### Setting DNS Resolver on Linux Client  
  
```bash
sudo apt install resolvconf -y
sudo systemctl start resolvconf.service && \
sudo systemctl enable resolvconf.service && \
sudo systemctl status resolvconf.service
```
  
```bash
sudo nano /etc/resolvconf/resolv.conf.d/head
```
```bash
# add  
nameserver 127.0.0.1
```
  
```bash
sudo resolvconf --enable-updates && \
sudo resolvconf -u && \
cat /etc/resolv.conf && \
sudo systemctl restart unbound
```

## Testing Unbound  
The first command should give a status report of SERVFAIL and no IP address.  
The second should give NOERROR plus an IP address.  
```bash
dig fail01.dnssec.works @127.0.0.1 -p 5335
```
```bash
dig dnssec.works @127.0.0.1 -p 5335
```
  
Unbound server will send a query to the DNS root servers.  
No need to specify forwarders.  
Benefit: Privacy - as you're directly contacting the responsive servers  
Drawback: Traversing the path may be slow, especially for the first time you visit a website  
Or setup trusted servers in the forward-zone:  
  
```bash
#forward-zone:
#    name: "."
#    forward-ssl-upstream: yes
#    forward-addr: 9.9.9.9@853#dns.quad9.net
#    forward-addr: 149.112.112.112@853#dns.quad9.net
```

### Unbound Cheat Sheet  

Verify configuration  
```bash
sudo unbound-checkconf
```

Unbound Status  
```bash
sudo unbound-control status
```

List Forwards  
```bash
sudo unbound-control list_forwards
```

Lookup on Cache  
```bash
sudo unbound-control lookup youtube.com
```

Dump Cache  
```bash
sudo unbound-control dump_cache > dns-cache.txt
```

Restore Cache  
```bash
sudo unbound-control load_cache < dns-cache.txt
```

Flush Cache  
Flush Specific Host  

```bash
sudo unbound-control flush www.youtube.com
```

Flush everything  
```bash
sudo unbound-control flush_zone .
```
