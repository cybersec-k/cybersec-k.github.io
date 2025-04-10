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

| Name            | [Vulnversity](https://tryhackme.com/room/vulnversity)                                  |
| ------------    | --------------------------------------------------------------------------------------|
| Difficulty      | Medium                                                                                |
| Tools           | nmap, Gobuster, Burpsuite, netcat                                                     |
| Topics          | Network Enumeration, Web Enumeration, SUID/GUID

## Reconnaissance using nmap

```bash
$ nmap -sV 10.10.246.93
┌──(root㉿kali)-[~]
└─# nmap -sV 10.10.246.93
Starting Nmap 7.93 ( https://nmap.org ) at 2025-04-10 23:52 UTC
Nmap scan report for ip-10-10-246-93.eu-west-1.compute.internal (10.10.246.93)
Host is up (0.0012s latency).
Not shown: 994 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.3
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
3128/tcp open  http-proxy  Squid http proxy 3.5.12
3333/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))
MAC Address: 02:1E:19:3B:E7:D5 (Unknown)
Service Info: Host: VULNUNIVERSITY; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.64 seconds
```
