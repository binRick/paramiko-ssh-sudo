#!/bin/bash
set -e
cd $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

__PASS=Q8DHmYMqXAksdf8yhU
__HOST=vpn299:22
__REMOTE=127.0.0.1:49225

EXPORTS="_HOST=$__HOST _REMOTE=$__REMOTE _HOST=$__HOST USER=bduser1 _PASS=$__PASS _KEY=$(pwd)/../../PARAMIKO_TEST_KEY.pub"
export $EXPORTS
CMD="./paramiko_sudo.py -u $_USER -r $_REMOTE -P $_PASS -K $_KEY -H $_HOST $@"
nodemon -w . -e py -x sh -- -c "$CMD"
