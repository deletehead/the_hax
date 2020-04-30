# Pentest Methodology
This will address methodology, things to remember, things to try if you're stuck, and things like these during pentests. The focus will be for a 5-day pentest focusing on stealing cardholder data or breaking into a segmented network; however, most of these techniques can be used for any type of offensive security engagement though.

The focus here is on steps to take, tools to run, things to check. Other files in this repo have the specific commands to run. I've linked to those where possible.

## Things to Not Forget
- Day 1: Focus on recon, scanning, and information gathering.
  - [ ] Begin scanning the target network segment to see if anything can reach it
  - [ ] If wireless is in scope, set this up and let it run/capture
  - [ ] Ask a contact to access the target network and verify the way they do it + document -- if remote, get documentation
  - [ ] Map out the network & target environment -- don't worry about exploitation yet, diligence in enumeration will pay off
  - [ ] Start password spraying soon, being mindful of lockout policy (just ask)

- Day 2: Focus on foothold
  - [ ] Attempt to get a foothold/creds if you don't already have one
  - [ ] Once you have a foothold, map out the directory enviro

## Open Source Intelligence
- [ ] Simply *Google the target*. What does the company do? What information do they store/process? What's their business?
- [ ] Check for sensitive documents:
  - [ ] Google: `site:firenation.com filetype:docx` (also: `doc`, `xls`, `xlsx`, `ppt`, `pptx`, `pdf`, etc)
- [ ] Identify high-profile employees (chairman of boards, CEO, CFO, CIO, CISO) or highly-privileged users (sysadmins, netadmins, devs, infosec)
Check photos for metadata or even interesting data captured. Examples could be badges, information on whiteboards, building layout.
- LinkedIn
  - [ ] Check employees. Look for security team, developers, admins. Get a feel for tech stack.
- [ ] Facebook
- [ ] Twitter
- [ ] Instagram
- [ ] Job Postings
  - [ ] What positions do they need filled?
  - [ ] What technology stack are they looking for/skills desired?
  - [ ] Recruiter contact info
- [ ] Emails
  - [ ] `theHarvester`
  - [ ] Other resources for emails: https://hunter.io, LinkedIn, etc.
  - [ ] Have you found any? What's the naming convention? Pull employees from LI and generate a list of usernames/emails for password spraying
- [ ] Harvest creds:
  - [ ] https://haveibeenpwned.com/
  - [ ] https://www.dehashed.com/
  - [ ] https://scylla.sh
- [ ] Github and source code repositories:
  - [ ] Search git for relevant repos
  - [ ] Look for developers identified in OSINT. Sometimes they put secrets or creds in personal repos. Tsk tsk tsk!
  - [ ] Try [`gitleaks`](https://github.com/zricethezav/gitleaks) or [`trufflehog`](https://github.com/dxa4481/truffleHog)
- [ ] PasteBin
  - [ ] Check for domains, company names, high-profile employees
- [ ] Cloud checks
  - [ ] Wide open S3 buckets? https://buckets.grayhatwarfare.com/

## Wireless

## Network Scanning & Enumeration
- [ ] Kick off a Nessus scan if applicable
- [ ] Scan the CDE/target environment: `masscan -iL cde.txt -p0-65535 -oG masscan-cde-allports`
- [ ] Ping sweep
- [ ] Kick off a big top 1024 scan. Don't forget to log it in case the scans hang up. Increase to `-T5` if you're feeling adventurous:
  ```
  mkdir scans
  nmap -iL subnets-firenation.lst -sV -sC -T4 -oA firenation-sV-sC --open --max-retries 1 --min-parallelism 128 --min-hostgroup 128 -v | tee scans/nmap.log
  ```
- [ ] Parse through open ports with: https://raw.githubusercontent.com/altjx/ipwn/master/nmap_scripts/nmapscrape.rb
- [ ] Perform reverse DNS lookups on the domain: `nmap -iL subnets-firenation.lst -sL -oA dns-lookup`
- [ ] Scan for SMB and for SMB Signing: `crackmapexec smb open-ports/445.txt | tee scans/cme-smb-scan.log`
- [ ] Scan for top MS vulns: `nmap -iL open-ports/445.txt -p445 --script=smb-vuln-ms08-067,smb-vuln-ms17-010 -v | tee scans/nmap-smb-vulns.log`
- [ ] Scan for BlueKeep (Win7 is a win, Win2k8 can DoS)
- [ ] Check for Jenkins instances. Typically runs on TCP/8080 (check `aquatone` output).
- [ ] SNMP checks
- [ ] `rpcclient` Check for NULL sessions, enum info if auth'd
- [ ] KRB guessing
- [ ] Check for `sa:sa` and similar


## Getting a Foothold
- [ ] Begin running [Responder](https://github.com/SpiderLabs/Responder):
  ```
  apt update && apt install -y responder
  responder -I eth0 -wrf
  ```
- [ ] Run [mitm6](https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/):
  ```
  pip install mitm6
  mitm6 -i eth0 -d firenation.com --debug 
  ```
  *Note: Every time I've run this, it has caused network disruptions. Proceed with caution and check out params `-hw` and `-hb`*    
- [ ] Relay NTLM authentication from the above poisoning (this specifically is for `mitm6`)
  ```
  ## Should relay to victim via SMB. Needs local admin (I think maybe RID500...need to verify)
  ntlmrelayx.py --ipv6 -wh wpad.firenation.com -of net-ntlmv2.hsh                   # Attempt to dump SAM 
  ntlmrelayx.py --ipv6 -wh wpad.firenation.com -of net-ntlmv2.hsh -c "systeminfo"   # Runs "systeminfo". Caught by CrowdStrike.
  ## LDAPS NTLM relay (patches may fix this!). Any Domain User can add up to 10 computers by default. Compy can be used for BloodHound.
  ntlmrelayx.py --ipv6 -wh wpad.firenation.com -t ldaps://dc.firenation.com --add-computer
  ##
  ```
- Multirelay with [new features for `ntlmrelayx.py`](https://www.secureauth.com/blog/what-old-new-again-relay-attack)
- Check for webmail/Exchange -- mailsniper, ruler, etc
    - https://github.com/sensepost/ruler/wiki/Homepage
    - Log in to O365 or internal and own their mailbox

## Local PrivEsc
- Local priv esc: 
    - https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation
    - https://book.hacktricks.xyz/windows/windows-local-privilege-escalation
    - https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS

## Lateral Movement & Domain PrivEsc
- [ ] Run BloodHound
  - Mark owned users and computers as you compromise them
  - Identify abusable attack paths
- [ ] Kerberoasting
- [ ] AS-REP roasting
- [ ] With owned accounts, log in to email and look for secrets. Try `CredSniper.ps1`. Also look at Teams, Skype history, etc. for juicies
- [ ] Run `CredNinja.py` against the network with the compromised accounts. See if you have local admin and can keep dumping hashes
- [ ] Check for SMB servers. Use `smbclient.py` and `plunder` to search for interesting files in those shares that you can access
- Check domain 


## Persistence & Data Exfil

## Web App Pentesting
