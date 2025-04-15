---
title: TryHackMe - Vulnversity
categories: [TryHackMe]
tags: []
media_subpath: /assets/images/tryhackme/vulnversity/
image:
  path: room_pic.png
---


## Overview

![room](room.png)

| Name            | [Vulnversity](https://tryhackme.com/room/vulnversity)                                 |
| ------------    | ------------------------------------------------------------------------------------- |
| Difficulty:     | Easy                                                                                  |
| Tools:          | nmap, Gobuster, Burpsuite, netcat                                                     |
| Topics:         | Network Enumeration, Web Enumeration, SUID/GUID

## Task 2: Reconnaissance using nmap

Start with `nmap` scan to get an overview of the target using the `-sV` flag

> -sV: Attempts to determine the version of the services running
{: .prompt-info }

```bash
$ nmap -sV 10.10.36.68
Starting Nmap 7.93 ( https://nmap.org ) 
Nmap scan report for ip-10-10-36-68.eu-west-1.compute.internal (10.10.36.68)
Host is up (0.0049s latency).
Not shown: 994 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.3
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
3128/tcp open  http-proxy  Squid http proxy 3.5.12
3333/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))
MAC Address: 02:63:12:1B:49:CD (Unknown)
Service Info: Host: VULNUNIVERSITY; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.67 seconds                                                      
```

We can see ports `21, 22, 139, 445, 3128 and 3333` are open and likely running `Ubuntu` OS

Web servers usually run on port `80` but here, the `Apache` web server is running on port `3333`. Might be interesting for further investigation

> Q. **Scan the box, how many ports are open?**<br>
  *><details><summary>Click for answer</summary>6</details>*

> Q. **What version of the squid proxy is running on the machine?**<br>
  *<details><summary>Click for answer</summary>3.5.12</details>*

> Q. **How many ports will nmap scan if the flag -p-400 was used?**<br>
  <details><summary>Click for answer</summary>400</details>

> Q. **What is the most likely operating system this machine is running?**<br>
  ><details><summary>Click for answer</summary>Ubuntu</details>

> Q. **What port is the web server running on?**<br>
  > *Answer: 3333*

> Q. **What is the flag for enabling verbose mode using Nmap?**<br>
  > *Answer: -v*

## Task 3: Locating directories using Gobuster
