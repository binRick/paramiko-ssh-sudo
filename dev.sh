#!/bin/bash
set -e
cd $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source .venv/bin/activate

__HOST=vpn299:22
__REMOTE=127.0.0.1:49225
_REMOTE_PORT=38229
__LOGS="-L /tmp/vpntech-bp/$UUID/ansible.log,/tmp/vpntech-bp/$UUID/audit.json"
__EXEC="-E /home/whmcs/.vpntech-tmp/.playEnvs/delegatedServer-${PLAY_ID}.sh"

export _HOST=$__HOST _REMOTE=$__REMOTE _HOST=$__HOST _USER=bduser1 _PASS=$__PASS 
export _KEY="$(pwd)/../../PARAMIKO_TEST_KEY.pub"
CMD="./paramiko_sudo.py -u $_USER -r $_REMOTE -P $_PASS -K $_KEY -H $_HOST -R $_REMOTE_PORT $__LOGS $__EXEC $@"
nodemon --delay 1 -w . -e py -x sh -- -c "$CMD"
