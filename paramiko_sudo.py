#!/usr/bin/env python3
import paramiko, os, json, sys
l_password = os.environ['PASS']
l_host = os.environ['HOST']
l_user = os.environ['USER']

COMMAND = 'id'

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(l_host, username=l_user, password=l_password)    
transport = ssh.get_transport()
session = transport.open_session()
session.set_combine_stderr(True)
session.get_pty()
session.exec_command("sudo -k {}".format(COMMAND))
stdin = session.makefile('wb', -1)
stdout = session.makefile('rb', -1)
stdin.write(l_password +'\n')
stdin.flush()
for line in stdout.read().splitlines():        
    print('host: %s: %s' % (l_host, line))
