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
## Network Scanning
## Getting a Foothold
## Local PrivEsc
## Lateral Movement & Domain PrivEsc
## Persistence & Data Exfil
## Web App Pentesting
