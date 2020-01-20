#!/bin/bash
set -e
cd $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

__PASS=Q8DHmYMqXAksdf8yhU
__HOST=vpn299

EXPORTS="_HOST=__HOST USER=bduser1 _PASS=$__PASS _KEY=./PARAMIKO_TEST_KEY.pub"
export $EXPORTS
CMD="./paramiko_sudo.py -u $_USER -r $_HOST -P $_PASS -K $_KEY $@"
nodemon -w . -e py -x sh -- -c "$CMD"
