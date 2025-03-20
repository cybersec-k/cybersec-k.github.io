---
title: "Port Scanning [p.101]"
author: Tri Nguyen
date: 2021-05-04 22:33:00 -0600
categories: [CEH, Chapter 3]
tags: [ceh, chapter3, port, note]
---

- Port scanners work by <mark>manipulating Transport layer protocol flags</mark> in order to identify active hosts and scan their ports.
### Port Scan Types
- Defined by 3 things: 
  1) Delivery packet's flags.
  2) Expected response.
  3) Stealth.
- 7 generic scan types:
  1. <b>Full Connect</b>: 
     - a.k.a <i>TCP connect</i> or <i>full open scan</i>.
     - Full connection, 3-way handshakes on ports.
     - Tear it down with RST in the end.
     - Most reliable but noisy.
     - Open ports will respond with SYN/ACK, close ports will respond with RST.
   2.  <b>Stealth</b>:
	     - Half-open scan, SYN scan.
	     - Only SYN packets are sent to ports.
	     - Response are the same as a full scan.
	     - Stealthy, possibly bypassing firewalls and monitoring efforts by hiding as normal traffic.
	     - No connection to be noticed.
  2. <b>Inverse TCP flag</b>:
		- Uses FIN, URG or PSH flag (or in one version, no flags at all).
		- Port open -> No response.
		- Port closed -> RST/ACK.
  3. <b>XMAS</b>:
	  - All flags are turned on -> packet "lit up" like a xmas tree.
	  - Response = Inverse TCP scan.
	  - Do not work against Windows (Microsoft TCP/IP is not RFC 793 compliant).
  4. <b>ACK flag probe</b>:
	  - ACK flags sent, look at return header: TTL or Window.
	  - TTL: if TTL of RST packet < 64 => open.
	  - Window: WINDOW of RST packet != 0 => open.
  5. <b>IDLE</b>:
	  - Spoofed IP to elicit port responses during a scan.
	  - Stealth.
	  - Uses SYN flag.
	  - Monitor responses as with a SYN scan.

- <b>IPID</b> (IP identifier) in the IP packet keeps track of fragmentation, increase by 1. => <mark>Used to spoof an IP address</mark>
- First, attacker use an <i>IDLE</i> machine.
- A packet <mark>(SYN/ACK)</mark> to this idle machine and notes the IPID of the respond.
- <mark>Response: RST</mark>. <i>Meaning: "I don't reckon this communication, start over?</i>.
- <b>With the IPID</b> in hand, attacker sends a <mark>SYN packet with spoofed IP to the victim.</mark>
- <i>If the port is open</i>, the victim will send a SYN/ACK to the zombie machine, the zombie machine will send back a RST, with IPID +=1.
- Attacker now send SYN/ACK to the zombie, if the result is IPID +=2 then the port is open.
- If IPID +=1 then the port is closed.
![Port open](https://i.imgur.com/49TihzT.png)
![Port close](https://i.imgur.com/s45qsL8.png)
![](https://i.imgur.com/qImsU1X.png)
#### UDP scan:
- Open: no response (there is no handshakes).
- Closed: ICMP port unreachable.