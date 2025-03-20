---
title: "[Knowledge] Red Team Reconnaissance"
author: Tri Nguyen
date: 2022-05-08 15:00:00 -0700
categories: [Tool, Knowledge, Cheatsheet, RedTeam]
tags: [tool, knowledge, cheatsheet, redteam]
pin: true
---

## Source
- https://tryhackme.com/room/redteamrecon

### whois
- A WHOIS server listens on TCP port 43 for incomming requests.
- The domain registrar is responsible for maintaining the WHOIS records for the domain names it is leasing.
- `whois` will query the WHOIS server to provide all saved records.
  - Registrar WHOIS server
  - Registrar URL
  - Record creation date
  - Record update date
  - Registrant contact info and address (unless withheld for privacy)
  - Admin contact info and address (unless witheld for privacy)
  - Tech contact info and address (unless withheld for privacy)

```
┌──(kali㉿kali)-[~/Desktop/blog/rcs-tringuyen.github.io]
└─$ whois thmredteam.com                                                      
   Domain Name: THMREDTEAM.COM
   Registry Domain ID: 2643258257_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.namecheap.com
   Registrar URL: http://www.namecheap.com
   Updated Date: 2021-10-13T20:54:46Z
   Creation Date: 2021-09-24T14:04:16Z
   Registry Expiry Date: 2022-09-24T14:04:16Z
   Registrar: NameCheap, Inc.
   Registrar IANA ID: 1068
   Registrar Abuse Contact Email: abuse@namecheap.com
   Registrar Abuse Contact Phone: +1.6613102107
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Name Server: KIP.NS.CLOUDFLARE.COM
   Name Server: UMA.NS.CLOUDFLARE.COM
   DNSSEC: unsigned
   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of whois database: 2022-05-08T23:07:06Z <<<

The Registry database contains ONLY .COM, .NET, .EDU domains and
Registrars.
Domain name: thmredteam.com
Registry Domain ID: 2643258257_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.namecheap.com
Registrar URL: http://www.namecheap.com
Updated Date: 0001-01-01T00:00:00.00Z
Creation Date: 2021-09-24T14:04:16.00Z
Registrar Registration Expiration Date: 2022-09-24T14:04:16.00Z
Registrar: NAMECHEAP INC
Registrar IANA ID: 1068
Registrar Abuse Contact Email: abuse@namecheap.com
Registrar Abuse Contact Phone: +1.9854014545
Reseller: NAMECHEAP INC
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Registry Registrant ID: 
Registrant Name: Redacted for Privacy
Registrant Organization: Privacy service provided by Withheld for Privacy ehf
Registrant Street: Kalkofnsvegur 2 
Registrant City: Reykjavik
Registrant State/Province: Capital Region
Registrant Postal Code: 101
Registrant Country: IS
Registrant Phone: +354.4212434
Registrant Phone Ext: 
Registrant Fax: 
Registrant Fax Ext: 
Registrant Email: e17b7976233e4e72a76b3dadb1d574bd.protect@withheldforprivacy.com
Registry Admin ID: 
Admin Name: Redacted for Privacy
Admin Organization: Privacy service provided by Withheld for Privacy ehf
Admin Street: Kalkofnsvegur 2 
Admin City: Reykjavik
Admin State/Province: Capital Region
Admin Postal Code: 101
Admin Country: IS
Admin Phone: +354.4212434
Admin Phone Ext: 
Admin Fax: 
Admin Fax Ext: 
Admin Email: e17b7976233e4e72a76b3dadb1d574bd.protect@withheldforprivacy.com
Registry Tech ID: 
Tech Name: Redacted for Privacy
Tech Organization: Privacy service provided by Withheld for Privacy ehf
Tech Street: Kalkofnsvegur 2 
Tech City: Reykjavik
Tech State/Province: Capital Region
Tech Postal Code: 101
Tech Country: IS
Tech Phone: +354.4212434
Tech Phone Ext: 
Tech Fax: 
Tech Fax Ext: 
Tech Email: e17b7976233e4e72a76b3dadb1d574bd.protect@withheldforprivacy.com
Name Server: kip.ns.cloudflare.com
Name Server: uma.ns.cloudflare.com
DNSSEC: unsigned
URL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/
>>> Last update of WHOIS database: 2022-05-08T00:07:19.26Z <<<
For more information on Whois status codes, please visit https://icann.org/epp

```
- We can gain lots of valuable information with only a domain name. 
- We might get lucky and find names, email, postal addresses, phone numbers.

## nslookup

## dig
- Domain Information Groper
- `dig` even allows you to specify a different DNS server to use. For example, using Cloudflare DNS server:
  - `dig @1.1.1.1 tryhackme.com`

## host
- Alternative for querying DNS servers for DNS records.

```
┌──(kali㉿kali)-[~/Desktop/blog/rcs-tringuyen.github.io]
└─$ host cafe.thmredteam.com
cafe.thmredteam.com has address 172.67.212.249
cafe.thmredteam.com has address 104.21.93.169
cafe.thmredteam.com has IPv6 address 2606:4700:3034::6815:5da9
cafe.thmredteam.com has IPv6 address 2606:4700:3034::ac43:d4f9

```

## traceroute / tracert

## Advance Search

| Syntax                           | Function                                          |
|----------------------------------|---------------------------------------------------|
| `search phrase`                  | Exact search phrase                               |
| `OSINT filetype:pdf`             | Find `pdf` files related to a certain term        |
| `salary site:blog.tryhackme.com` | Limit result to a specific site                   |
| `pentest -site:example.com`      | Exclude a specific site                           |
| `walkthorugh intitle:TryHackMe`  | Find pages with a specific term in the page title |
| `challenge inurl:tryhackme`      | Find pages with a specific term in the page url   |

- [Google Advanced Search](https://www.google.com/advanced_search)
- [Google Refine Web Searches](https://support.google.com/websearch/answer/2466433)
- [DuckDuckGo Search Syntax](https://help.duckduckgo.com/duckduckgo-help-pages/results/syntax/)
- [Bing Advanced Search Options](https://help.bing.microsoft.com/apex/index/18/en-US/10002)

- Can lead to confiential information such as:
  - Documents for internal company use
  - Confidential spreadsheets with usernames, emails, even passwords
  - Files containing usernames
  - Files containing usernames
  - Sensitive directories
  - Service version number (some of which might vulnerable and unpatched)
  - Error messages

- Specific advanced Google search terms that can lead to confidential informations:
  - [Google Hacking Database](https://www.exploit-db.com/google-hacking-database)
  - Example:
    - **Footholds**
    Consider GHDB-ID: 6364 as it uses the query `intitle:"index of" "nginx.log"` to discover Nginx logs and might reveal server misconfigurations that can be exploited.
    - **Files Containing Usernames**
    For example, GHDB-ID: 7047 uses the search term `intitle:"index of" "contacts.txt"` to discover files that leak juicy information.
    - **Sensitive Directories**
    For example, consider GHDB-ID: 6768, which uses the search term `inurl:/certs/server.key` to find out if a private RSA key is exposed.
    - **Web Server Detection**
    Consider GHDB-ID: 6876, which detects GlassFish Server information using the query `intitle:"GlassFish Server - Server Running"`.
    - **Vulnerable Files**
    For example, we can try to locate PHP files using the query intitle:`"index of" "*.php"`, as provided by GHDB-ID: 7786.
    - **Vulnerable Servers**
    For instance, to discover SolarWinds Orion web consoles, GHDB-ID: 6728 uses the query `intext:"user name" intext:"orion core"` -solarwinds.com.
    - **Error Messages**
    Plenty of useful information can be extracted from error messages. One example is GHDB-ID: 5963, which uses the query `intitle:"index of" errors.log` to find log files related to errors.

## Social Media
- LinkedIn, Twitter, Facebook, Instagram, Glassdoor, etc.

## Job Ads
- Revealing names and emails
- Could give insights to the company's tech stack, systems and infrastructure.
- [Wayback Machine](https://archive.org/web/) can be useful to retrieve previous versions of a job opening page.

## ViewDNS.info
- It is common nowadays to share an IP address across web server.
- Using reverse IP lookup, we can find other servers sharing the same IP addresses used by a domain name.

## Threat Intelligence Platform
- https://threatintelligenceplatform.com/
- Launch a series of tests from malware checks to WHOIS and DNS queries.

## Censys Search
- https://search.censys.io/
- Provide information about IP addresses and domains.

## Shodan
- You can use Shodan from the command line: https://cli.shodan.io/
- E.g. to find your Internet-facing IP: `shodan myip`

## Recon-ng
- A framework that helps automate OSINT work.
### 1. Creating a Workspace
- `workspaces create WORKSPACE_NAME`
- `recon-ng -w WORKSPACE_NAME` starts recon-ng with the specific workspace.

### 2. Seeding the Database
- `db schema` to check the names of the tables in our database.
- `db insert domains` to insert the domain name into the domains table.

### 3. Recon-ng Marketplace
- We will search for suitable modules from the marketplace.
- Useful commands related to marketplace usage:
  - `marketplace search KEYWORD` to search for available modules with _keyword_.
  - `marketplace info MODULE` to provide information about th emodule in question.
  - `marketplace install MODULE` to install the specified module into Recon-ng.
  - `marketplace remove MODULE` to uninstall the specified module.
- Multiple categories, such as discovery, import, recon and reporting.
- `marketplace search` to get a list of all available modules
  - E.g.: `marketplacec search domains-` to search for modules containing `domains-`
- `marketplace install google_site_web` 

### 4. Working with Installed Moduled
- `modules search` to get a list of all the installed modules
- `modules load MODULE` to load a specific module to memory
- E.g.: `module load viewdns_reverse_whois`.
- To `run` it, we need to set the required options:
  - `options list` to list the options that we can set for the loaded module.
  - `options set <option> <value>` to set the value of the option.

### 5. Keys
- Some modules cannot be used without a key fro the respective service API. `K` indicates that you need to provide the relevant service key to use the module in question.
  - `keys list` lists the key
  - `keys add KEY_NAME KEY_VALUE` adds a key
  - `keys remove KEY_NAME` removes a key
- `options list` list the available options for the chosen module.
- `options set NAME VALUE`

## Maltego
- Application blends mind-mapping with OSINT.
- Start with a domain name, company name, person's name, email, etc.