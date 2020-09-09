# External Pentest Methodology
Focus of this will be external penetration tests. This includes both network and application-layer. This will generally be in order, and a checklist of things never to forget.

A word on webapps: ask for source code wherever available. OWASP states that a black box review is just not enough, and white box review will be much more comprehensive. It says:
> While black-box penetration test results can be impressive and useful to demonstrate how vulnerabilities are exposed in a production environment, they are not the most effective or efficient way to secure an application. It is difficult for dynamic testing to test the entire code base, particularly if many nested conditional statements exist. If the source code for the application is available, it should be given to the security staff to assist them while performing their review. It is possible to discover vulnerabilities within the application source that would be missed during a black-box engagement.

## Schedule
- Spend the first day or two in OSINT, automated scanning, and all network-level testing
- Spend the rest of the time on application-level testing

## Key Tooling
- Nessus
- Burp Suite Pro
- Other tools on Kali Linux

## Questions to Answer
- [ ] Are there any services open to the Internet that shouldn't be?
  - [ ] Are there any administrative services (SSH/RDP/etc.) that aren't protected by MFA?
    - If there are, it's a finding. If not, get a second opinion based on their situation if this should be a finding or not.
  - Services such as NTP, SNMP, etc. should be a finding and PCI fail if compliance-oriented test
  - ENSURE that these really are in scope for CDE.

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
- [ ] From initial discovery and scanning, list out all web applications (including backend APIs) to test
- [ ] Take each app and poke around it with Burp proxy to get some passive discovery
  - [ ] Check server responses and headers for interesting information (frameworks, web server, scripting languages, etc)
  - [ ] Can you determine a web framework from the cookies being sent? ex. CakePHP
  - [ ] Check HTML source for things like comments including passwords or SQL queries, indications on other frameworks or libraries like Telerik
  - [ ] Note GETs and POSTs
- [ ] Note:
  - Web server, frameworks, general tech stack
  - `robots.txt` and similar meta files
- [ ] If known frameworks (Wordpress, Drupal, etc.) are in use, investigate for known vulnerabilities
  - Try `wpscan`, `droopescan`, etc.
- [ ] Check HTTP methods (usually done by Nessus, etc.)
- [ ] Brute force files and extensions with `gobuster`
  - Identify the type of tech used and check the appropriate extensions (`php`, `aspx`, etc.)
  - [Check for interesting extensions, too](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/03-Test_File_Extensions_Handling_for_Sensitive_Information.html). Ex. `zip`, `asa`, `config`, `inc`, `bak`, and `txt`

## Web Application Pentest
- [ ] Passively scan with Burp and check for quick/boring wins: HSTS, cookie settings (secure flag, HttpOnly, etc), cert issues, etc.
- [ ] Test file uploads:
  - Uploading other extensions (ex. `phtml`) to bypass blacklists/filters
- [ ] Subdomain takeover
- [ ] Test [role definitions](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/01-Test_Role_Definitions.html)
- [ ] Can you [enumerate usernames](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account.html)?
- [ ] Authentication
  - Creds sent in the clear?
  - Check default or easy creds
  - Check default creds for fresh accounts...is there a pattern?
  - See if you can brute force or bypass front end lockout policies
  - Check for [vulnerable forgot password](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/05-Testing_for_Vulnerable_Remember_Password.html)
  - Check for [weak password policy](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/07-Testing_for_Weak_Password_Policy.html)
  - If the app uses security questions, [check these too](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/08-Testing_for_Weak_Security_Question_Answer.html)
- [ ] Authorization
  - Check to see if you can access things you shouldn't be able to (e.g. admin resources as a lowpriv user)
- [ ] Session Management
  - Note the cookies used by the app, and see where they are set (what portions of the app generate cookies)
  - Are the cookies/tokens secure and unpredictable? Basic cryptanalysis -- do you notice parts of the cookie data that are similar/the same?
  - Check dem JWTs
  - Are cookies marked as secure?
- [ ] Input validation
  - Get interesting requests, and start actively scanning them with BurpPro (remember to be mindful of authentication)
  - When looking through Burp traffic, make sure to keep an eye out for values that look like objects (I've found direct code injection this way, and of course object injection)




