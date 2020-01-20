#!/bin/bash
nodemon -w . -e py -x sh -- -c "HOST=vpn299 USER=bduser1 PASS=Q8DHmYMqXAksdf8yhU ./paramiko_sudo.py $@"
