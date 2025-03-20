---
title: "[hackertest.net] Write Up"
author: Tri Nguyen
date: 2021-11-20 23:00:00 -0700
categories: [CTF, Write Up, Wargame]
tags: [ctf, write-up, hackertest]
---

Link: http://www.hackertest.net/

# Level 2

- Inspecting element you can see the check `check()` function.

```javascript
{
var a="null";
function check()
{
if (document.a.c.value == a)
{
document.location.href="http://www.hackertest.net/"+document.a.c.value+".htm";
}
else
{
alert ("Try again");
}
}
}
```

- Notice that variable `a` is the STRING `'null'`. Javascript's null is just `null`.

- Password is `null`.

# Level 3

- Inpect

```javascript
var pass, i;
pass=prompt("Please enter password!","");
if (pass=="l3l") {
window.location.href="http://www.hackertest.net/"+pass+".htm";
i=4;
}
```

- The password is hardcoded as `l3l`

# Level 4

```javascript
function pass() {
    var pw, Eingabe;
    pw = window.document.alinkColor;
    Eingabe = prompt("Please enter password");
    if (Eingabe == pw) {
        window.location.href = String.fromCharCode(97, 98, 114, 97, 101) + ".htm";
    } else {
        alert("Try again");
    }
}
```
- Type `window.document.alinkColor` in the browser's Console, you see the password is `#000000`

# Level 5

- You will be redirected to another page.

- This page disables right click. So you have to use the shortcut to open the Console (`Ctrl+Shift+K` for Firefox and `Ctrl+Shift+J` for Chrome).

- But it also disable inspecting.

- After turn off the page from reloading -> It finally shows.

```javascript
var pass, i;
pass = prompt("Password: ", "");
if (pass == "SAvE-as hELpS a lOt") {
    window.location.href = "save_as.htm";
    i = 4;
} else {
    alert("Try again");
    window.location.href = "abrae.htm";
}
```

- `SAvE-as hELpS a lOt`

# Level 6

- Nothing in the `<script>` tags like before.

- But the file does referring to a JS called `psswd.js`

- Go to http://www.hackertest.net/psswd.js you will see the password.

- (Alternatively) You can save the webpage. Using Save-As.

- `hackertestz`

# Level 7

- The form send a request to `/pwd2.php`.

- I tried intercept it with Burp to inspect but nothing strange was happening.

- The php file has nothing to show.

- The level name is `included`. So I inspect the HTML again (By viewing page source).

- Found `<body bg="images/included.gif">`

- Go to this address http://www.hackertest.net/images/included.gif you will see the credentials.

- `phat:jerkybar3`

# Level 8

- This level is weird. Not in a good way.

- Go to `/image/phat.gif`. There a hint: `Look for a .PhotoShop Document`

- Change to `/image/phat.psd`. You will download a file.

- Open with GIMP. Turn off all the watermark layers, you will see the credentials.

- `zadmin:stebbins`

# Level 9

- Crack the password. Inspecting the HTML you will see the string `Z2F6ZWJydWg=` in the comment.

- Base64 decode to `gazebruh`.

- Go to `/gazebruh.php` -> Our level 10.

# Level 10

- Nothing special when looking and browsing through the source code.

- There are however weird __italic__ words

- Combined them you got `Shackithalf`. I tried this but it not working.

- Turned out, lowercase -_- `shackithalf`

# Level 11

- Again looking closely at the source code you will see `clipart.php`

# Level 12

- Grab the global picture and zoom in SUPER CLOSE. `puta.php`

# Level 13

- This time the picture is `Level 13`.

- Download it and zoom close, will see `4xml`

- Go to `4xml.php`

# Level 14

- Download the `bidvertiser.gif` and use GIMP.

- The first layer is `TOTALLY!!! php`

- `totally.php`

# Level 15

- Before I went down the rabbit hole why the image is not printing, `xxd pass2level16.jpg` return:

```shell
┌──(kali㉿kali)-[~/Downloads]
└─$ xxd pass2level16.jpg                                                                                                                 1 ⨯
00000000: ffd8 ffe0 2010 4a46 4946 2001 0220 2064  .... .JFIF ..  d
00000010: 2064 2020 ffec 2011 4475 636b 7920 0120   d  .. .Ducky . 
00000020: 0420 2020 5020 20ff ee20 0e41 646f 6265  .   P  .. .Adobe
00000030: 2064 c020 2020 01ff db20 8420 0202 0202   d.   ... . ....
00000040: 0202 0202 0202 0302 0202 0304 0302 0203  ................
00000050: 0405 0404 0404 0405 0605 0505 0505 0506  ................
00000060: 0607 0708 0707 0609 090a 0a09 090c 0c0c  ................
00000070: 0c0c 0c0c 0c0c 0c0c 0c0c 0c0c 0103 0303  ................
00000080: 0504 0509 0606 090d 0b09 0b0d 0f0e 0e0e  ................
00000090: 0e0f 0f0c 0c0c 0c0c 4c65 7665 6c20 3136  ........Level 16
000000a0: 3a20 756e 6176 6169 6c61 626c 650f 0f0c  : unavailable...
000000b0: 0c0c 0c0c 0c0f 0c0c 0c0c 0c0c 0c0c 0c0c  ................
000000c0: 0c0c 0c0c 0c0c 0c0c 0c0c 0c0c 0c0c 0c0c  ................
000000d0: 0c0c ffc0 2011 0820 0f20 0f03 0111 2002  .... .. . .... .
000000e0: 1101 0311 01ff c420 4b20 0101 2020 2020  ....... K ..    
000000f0: 2020 2020 2020 2020 2020 2009 0101 2020             ...  
00000100: 2020 2020 2020 2020 2020 2020 2020 1001                ..
00000110: 2020 2020 2020 2020 2020 2020 2020 2020                  
00000120: 1101 2020 2020 2020 2020 2020 2020 2020  ..              
00000130: 2020 ffda 200c 0301 2002 1103 1120 3f20    .. ... .... ? 
00000140: bf80 2020 3fff d9                        ..  ?..
```

- Tried `/unavailable.php` not working

- But trying `/unavailable` take me to level 16!

# Level 16

- Try going to `hackertest.net/images` but got a nice try ;)

- Go to `hackertest.net/unavailable/images` you will got a `bg.jpg` file.

- `xxd bg.jpg` will return a big chunk.

- If you scroll to the top, you will see `Ducky.php`

# Level 17

- The url is `hackertest.net/unavailable/ducky.php`

- Inspect the source code:

```html
<font color="#FFFFFF">Password: your IP address</font><br>
```

# Level 18

- The url is `hackertest.net/level18.shtml`

- Hey somehow your Console is blocking the password LOL.

- `/level19.shtml`

# Level 19

- There is a file call `level20_pass.gif`

- Download and open it with GIMP

- You will see `gazebruh2`.

- Go to `hackertest.net/gazebruh2.htm`

# Level 20

- The first long string is ASCII encoded message of saying congratulation.

- The second long string is a multi-base64-encoded string.

- You will get `streetkorner.net/gb`

- I went there but there were nothing.

- However, inspecting the source code, you will see a hint.

    >  ^^^^^^^^^^ Change domain, add "22332" at the end, reach it and then get hold of ... ^^^^^^^^^^ 

- So go to `hackertest.net/gb22332`

- It said 505 but the actual status code is 200

- Go to `hackertest.net/505`

- It said 403, but again go to `hackertest.net/505/403`

- It said `What is the answer to life, the universe, and everything?`

- If you google this it will return `42` hmmm... In the inspector, it also said you should add extension to that.

- I tried `hackertest.net/505/403/42.xxx` but none was working.

- Turn out it was `hackertest.net/42.php` LOL

- Done! You will get the secret code of `seoJimWseo`!

