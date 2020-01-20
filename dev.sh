#!/bin/bash
set -e
cd $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

__PASS=Q8DHmYMqXAksdf8yhU
__HOST=vpn299:22
__REMOTE=127.0.0.1:49225

export _HOST=$__HOST _REMOTE=$__REMOTE _HOST=$__HOST _USER=bduser1 _PASS=$__PASS 
export _KEY="$(pwd)/../../PARAMIKO_TEST_KEY.pub"
CMD="./paramiko_sudo.py -u $_USER -r $_REMOTE -P $_PASS -K $_KEY -H $_HOST $@"
nodemon --delay 1 -w . -e py -x sh -- -c "$CMD"
