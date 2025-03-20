---
title: "[OverTheWire] [Leviathan] Report"
author: Tri Nguyen
date: 2021-11-20 14:20:00 -0700
categories: [CTF, Write Up]
tags: [ctf, write-up, overthewire, leviathan]
---

_Link_: https://overthewire.org/wargames/leviathan/

# Level 0->1

```shell
$ ssh leviathan0@leviathan.labs.overthewire.org -p 2223
```
- `ls` shows nothing.
- I tried to enumerate `/etc/leviathan_pass` but no access to `leviathan1` file.
- `ls -la` the home directory.
- `.backup` is suspicious.
- Go into this folder there is a `bookmark.html` file.

```shell
$ cat bookmark.html | grep leviathan1
<DT><A HREF="http://leviathan.labs.overthewire.org/passwordus.html | This will be fixed later, the password for leviathan1 is rioGegei8m" ADD_DATE="1155384634" LAST_CHARSET="ISO-8859-1" ID="rdf:#$2wIU71">password to leviathan1</A>
```
- The password is `rioGegei8m`

# Level 1->2

- We see an executable called `check` in the home directory.
- You need to enter a password.
- Things I tried at first but no result.

```shell
$ file check
$ strings check
```

- But we know this is a C file.
- I went down the rabbit hole while trying to use `gdb` and `Ghidra` to decompile the file. (Maybe I'm bad lol)
- We know that the program is comparing the user input with a hardcoded string via `strcmp()` function.
- Lastly I used

```shell
$ ltrace ./check
```
- We got our password is `sex`
- Once you get past this you will become leviathan2
- The password is `ougahZi8Ta`

# Level 2->3

- This one is a bit trickier.
- When decompiling `printfile` it will shows that the program try to run `access()` with leviathan2 privilege but try to `cat` the file with leviathan3 privilege.
- After googling, we can create a symlink as a PoC.
- I tried to create a symlink to `/etc/leviathan_pass/leviathan3` in `/tmp`
- Doesn't seem to work too well.
- Another look at the decompiled code, the program seems to read all of our input WHILE `cat` can only the FIRST parameter.
- So if our input is "A B.txt", it will only `cat A`

```c
iVar2 = access((char *)param_2[1],4);
if (iVar2 == 0) {
    snprintf(local_210,0x1ff,"/bin/cat %s",(char *)param_2[1]);
    __euid = geteuid();
    __ruid = geteuid();
    setreuid(__ruid,__euid);
    system(local_210);
    uVar1 = 0;
}
...
```

- Knowing that I did the following:

```shell
$ cd /tmp/tlnguyen
$ ln -s /etc/leviathan_pass/leviathan3 leviathan3
$ touch "leviathan3 file.txt"
$ ~/printfile "leviathan3 file.txt"
Ahdiemoo1j
/bin/cat: file.txt: No such file or directory
```

- The password is `Ahdiemoo1j`

# Level 3->4

- This one is actually easy.
- If you `ltrace ./level3` you will see 2 `strcmp()` with one being a decoy.

```shell
leviathan3@leviathan:~$ ltrace ./level3
__libc_start_main(0x8048618, 1, 0xffffd784, 0x80486d0 <unfinished ...>
strcmp("h0no33", "kakaka")                                                             = -1
printf("Enter the password> ")                                                         = 20
fgets(Enter the password> WHAT
"WHAT\n", 256, 0xf7fc55a0)                                                       = 0xffffd590
strcmp("WHAT\n", "snlprintf\n")                                                        = -1
puts("bzzzzzzzzap. WRONG"bzzzzzzzzap. WRONG
)  
```

- The real password is `snlprintf`
- Once done you will get a shell and can see leviathan4's password
- `leviathan4:vuH0coox6m`

# Level 4->5

- This one only gets ... easier ???
- Discover `.trash/.bin`
- `cat` this one seems to be binary file
- Easy, convert it to ascii

```shell
leviathan4@leviathan:~/.trash$ ./bin
01010100 01101001 01110100 01101000 00110100 01100011 01101111 01101011 01100101 01101001 00001010 
leviathan4@leviathan:~/.trash$ ./bin | perl -lape '$_=pack"(B8)*",@F'
Tith4cokei
```

- `leviathan5:Tith4cokei`

# Level 5->6

- Still, this one is easier than Level 2->3 LOL.
- Using `ltrace` you will find out that the executable will try to `fopen()` a file at `/tmp/file.log`
- Create a file there, run `leviathan5`, it will read the file's content and delete that file!
- Needless to say, this will be excuted with leviathan6's privilege.
- I tried to create a bash executable that will print out `leviathan6`'s password but no luck.
- Correct guess, create a symlink to `/etc/leviathan_pass/leviathan6`!

```shell
leviathan5@leviathan:~$ ln -s /etc/leviathan_pass/leviathan6 /tmp/file.log
leviathan5@leviathan:~$ ./leviathan5
UgaoFee4li
```

- `leviathan6:UgaoFee4li`

# Level 6->7

- `leviathan6` takes in your 4 digit code.
- Pass this bad boy to Ghidra, in the decompile code, you will see this excerpt:

```c
{
  int iVar1;
  __uid_t __euid;
  __uid_t __ruid;
  
  if (param_1 != 2) {
    printf("usage: %s <4 digit code>\n",*param_2);
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  iVar1 = atoi((char *)param_2[1]);
  if (iVar1 == 0x1bd3) {
    __euid = geteuid();
    __ruid = geteuid();
    setreuid(__ruid,__euid);
    system("/bin/sh");
  }
  else {
    puts("Wrong");
  }
  return 0;
}
```

- `0x1bd3` convert to Decimal is `7123`
- Now run `./leviathan6 7123` you will get a shell!
- `leviathan7:ahy7MaeBo9`

# Level 7->8

- Oh this is done lol! You will find a `CONGRATULATIONS` file.

