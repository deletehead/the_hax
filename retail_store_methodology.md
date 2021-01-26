# Retail Store Penetration Test
General methodology for testing a retail store. The test will be in two phases: POS device and then LAN.

## General
- Call the store contact first and ensure they know you're coming and are ready
- Ensure they check ID to verify you are who you say
- Examine network equipment inside administrative interfaces for default passwords
- Basic physical security checks:
  - Are doors/cabinets/etc. locked?
  - Call out anything that's weird/off/abusable

## POS Testing
- Ask if they use a wireless/mobile device in the store. They might not know of a wireless network but it could be hidden and dedicated for devices. Also, check those for payment software/processing.
- Get a photo/documentation of the make/model/serial number of the device
- Examine the POS Pin Entry/Terminal Devices for tampering. Determine if the devices are constrained in any way, or would be susceptible to removal and replacement (e.g. are not locked down)
- Test the POS for common vulnerabilities.
- Is autologon being used?
- Is kiosk mode enabled? Can you bust out of it? Is it easy for staff (i.e. intended breakout) or malicious user to do?
- Can you upload malware from the local net in some way?
- Can you reach the Internet and download malware?
- Can you modify POS software in some way? Esp note if this is possible with an autologon user context
- Attempt unauthorized updates
- Is AV used?
- Is app whitelisting used? Can you bypass it through any known means?
- Try your plunderbug to tap the connection between POS and switch. Also use it between pinpad and wherever that's plugged in.
- Is there exposed USBs you can plug a bash bunny/rubber ducky in?
- Can you scan the storage for unencrypted PAN?
- Are there wireless POS devices in addition to hardwired?

## LAN Testing
- Note the subnets, etc. for scoping information
- Connect an unauthorized new device on each network switch or hub and test for (a) accessibility to network and (b) DHCP addresses being provided
- If Wireless is in use, attempt to obtain the pre-shared key and connect to the network. Record/document SSIDs and verify which ones are owned by target corp.
  - WEP is an autofail. Crack it with extreme prejudice.
  - WPS is also an auutofail. Crack it.
- Complete standard Network & OS tests of back-office and manager systems. Remember, you're looking for PAN.
- Look for common MITM vulnerabilities: `mitm6` and ARP poisoning.
  - Only do ARP poisoning if you can do it _safely_ and targeted against a dedicated testing machine. Don't bring down the entire store.
- Look for other poisoning attacks: LLMNR/NBNS
- Test the ability to reach the corporate network
- Test the ability to reach other stores
- Document and test the use of remote access tools such as VNC and Microsoft RDP
- Can you pivot in some way to CDE?

## Success Criteria
You win if:
- Direct observation of PAN during transmission to back-end systems
- Compromise of POS systems with the ability to read memory and/or capture input.
- Successful compromise of systems in the CDE through connectivity provided by the retail network.
The success criteria will be different for every engagement and environment and should be established during the kick-off call prior to testing.
