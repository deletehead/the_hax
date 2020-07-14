# External Pentest Methodology
Focus of this will be external penetration tests. This includes both network and application-layer. This will generally be in order, and a checklist of things never to forget.

A word on webapps: ask for source code wherever available. OWASP states that a black box review is just not enough, and white box review will be much more comprehensive. It says:
> While black-box penetration test results can be impressive and useful to demonstrate how vulnerabilities are exposed in a production environment, they are not the most effective or efficient way to secure an application. It is difficult for dynamic testing to test the entire code base, particularly if many nested conditional statements exist. If the source code for the application is available, it should be given to the security staff to assist them while performing their review. It is possible to discover vulnerabilities within the application source that would be missed during a black-box engagement.

## Key Tooling
- Nessus
- Burp Suite Pro
- Other tools on Kali Linux

## OSINT
- [ ] Run `discover.sh`
  - This will include DNS information, whois, etc.
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

## Network Scanning
- [ ] Fire off a Nessus scan for the provided scope
- [ ] Kick off an nmap scan: `nmap -iL cde.lst -sVC -p- --max-retries=1 -v -oA scans/nmap-sVC-allports --min-hostgroup=128 | tee nmap.log`
- [ ] When that's done, do a UDP scan: `nmap -iL cde.lst -sU --max-retries=1 -v -oA scans/nmap-sU-top1k --min-hostgroup=128 | tee nmap.log`
- [ ] Exploit where applicable
- [ ] Investigate all findings, collect evidence, organize notes

## Application Mapping
- From initial discovery and scanning, list out all web applications (including backend APIs) to test
- Take each app and poke around it with Burp proxy to get some passive discovery

## Web Application Pentest
