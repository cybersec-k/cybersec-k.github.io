# [Simple CTF][1]

[Link: https://tryhackme.com/room/easyctf](https://tryhackme.com/room/easyctf)

Let's start with a nmap scan of the target

`nmap -sV -sC <IP>`

`-sV: Probe open ports to determine service/version info`

`-sC: script scan using default scripts`

![Nmap Scan](images/scan.png)

Lots of interesting info to dig through. Firstly, we see there's three ports open: `21, 80, 2222`

## 1. How many services are running under port 1000?
> ***2***

## 2. What is running on the higher port?
> ***SSH***

Let's do some enumeration on the target using GoBuster to look for hidden files and URL paths.

We'll need a wordlist that contains common terms so let's see what TryHackMe provides.

![wordlist search](images/find_wordlists.png)

![wordlists](images/wordlists1.png)

Check out the `common.txt` which should suffice for our needs

![wordlists](images/wordlists2.png)

`gobuster dir -u <IP> -w /root/Desktop/Tools/wordlists/dirb/common.txt`

`dir: uses directory/file bruteforcing mode `

`-u: url`

`-w: wordlist`

![GoBuster](images/gobuster.png)

We get some `403` forbidden resources, a `200` OK response for `robots.txt`, and a `301` moved permanently `simple` path.

Checking `robots.txt` first tells us a possible username by `mike` and that the CUPS server shouldn't be indexed.

![robots.txt](images/robots_txt.png)

Now checking out the `simple` path

![simple](images/simple.png)

There's an interesting section that mentions logging into the admin panel. Will keep in mind for later.

![admin](images/admin.png)

At the bottom, we see the server is powered by `CMS Made Simple version 2.2.8` so lets plug that into searchsploit to see if there's any vulnerabilities 

![cms](images/cms_version.png)

`searchsploit CMS Made Simple 2.2.8

![Searchsploit](images/searchexploit.png)

The results turn up a SQL Injection vulnerability with versions under 2.2.10 and the exploit is located in `/opt/searchsploit/exploits/php/webapps/46635.py`

Checking the python file gives some useful information on the vulnerability

![CVE Details](images/cve.jpg)

## 3. What's the CVE you're using against the application?
> ***CVE-2019-9053***

*To what kind of vulnerability is the application vulnerable?*
> ***SQLi***

Run the file -> `sudo python /usr/share/exploitdb/exploits/php/webapps/46635.py`

![Run file](images/run_tech.jpg)

> If you have an error for *termcolor*.

![Python Error](images/python_error.jpg)

Download the **binaries** from the [Official Website][3]. Unzip the file using command `tar -xf <file_name>`. Change directory to the extracted folder and run `sudo python setup.py install`. This will solve your termcolor error.

Run the file with `sudo python usr/share/exploitdb/exploits/php/webapps/46635.py -u http://<IP>/simple --crack -w /usr/share/seclists/Passwords/Common-Credentials/best110.txt`

![Script Run](images/script_run.jpg)

> The user credential is `mitch:secret`

*What's the password?*
> **secret**

As we know `ssh` is open. Let's try to connect -> `ssh mitch@<IP> -p 2222`

![SSH](images/ssh.jpg)

*What's the user flag?*

![User Flag](images/user_flag.jpg)

*Is there any other user in the home directory? What's its name?*
> ***sunbath***

![Other User](images/other_user.jpg)

*What can you leverage to spawn a privileged shell?*
> ***vim***

![Privilege Escalation](images/priv_escal.jpg)

First let's make this shell stable by typing -> `python3 -c 'import pty;pty.spwan("/bin/bash")'`.

![Stable Shell](images/shell_stable.jpg)

I searched online for privilege escalation for `vim` and I got a link from [GTFOBins][4].

Run the commands.

![Vim Escalate](images/vim_escal.jpg)

*What's the root flag?*

![Root Flag](images/root_flag.jpg)

[1]: https://tryhackme.com/room/easyctf
[2]: https://blog.hackhunt.in/search/label/Nmap
[3]: https://pypi.org/project/termcolor/#files
[4]: https://gtfobins.github.io/gtfobins/vim/
