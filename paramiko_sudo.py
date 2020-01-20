#!/usr/bin/env python3
from __future__ import print_function
import paramiko, os, json, sys, socket, select, threading, traceback, subprocess, time, getpass
from optparse import OptionParser

PTY_ENV = {'abc':'def','wow':123}

PTY_TERM = 'xterm-256'
PTY_WIDTH = 160
PTY_HEIGHT = 24
PTY_WIDTH_PIXELS = 0
PTY_HEIGHT_PIXELS = 0    

EXEC_TIMEOUT = 10
DSTAT = 'dstat -alp --top-cpu --top-cputime-avg 5 1500'
SSH_PORT = 22
HELP = """\
Paramiko SSH Test
"""

COMMANDS = ['id','ls /','find /']
COMMANDS = ['id','ls /','tail -f /var/log/messages']
COMMANDS = ['id','ls /','journalctl -f']
COMMANDS = ['id','ls /a']
COMMANDS = ['id','ls /','env']
COMMANDS = ['id','ls /',DSTAT]

SH_ARGS = "i"
COMMAND = ' && '.join(COMMANDS)
SUDO_ARGS='-k -H -u root'
g_verbose = True

def generateEnvironmentString():
    PTY_ENV_STR = ''
    for k in PTY_ENV.keys():
        PTY_ENV_STR += ' {}={}'.format(k,PTY_ENV[k])
    return PTY_ENV_STR

def generateSudoCommand():
    return "command sudo {} {} sh -{}c \"{}\"".format(SUDO_ARGS, generateEnvironmentString(), SH_ARGS, COMMAND)

def verbose(s):
    if g_verbose:
        print(s)

def get_host_port(spec, default_port):
    args = (spec.split(":", 1) + [default_port])[:2]
    args[1] = int(args[1])
    return args[0], args[1]

def parse_options():
    global g_verbose

    parser = OptionParser(
        usage="usage: %prog [options] <ssh-server>[:<server-port>]",
        version="%prog 1.0",
        description=HELP,
    )
    parser.add_option(
        "-q",
        "--quiet",
        action="store_false",
        dest="verbose",
        default=True,
        help="squelch all informational output",
    )
    parser.add_option(
        "-P",
        "--password",
        action="store",
        type="string",
        dest="password",
        default=False,
        help="ssh pass",
    )
    parser.add_option(
        "-u",
        "--user",
        action="store",
        type="string",
        dest="user",
        default=getpass.getuser(),
        help="username for SSH authentication (default: %s)"
        % getpass.getuser(),
    )
    parser.add_option(
        "-r",
        "--remote",
        action="store",
        type="string",
        dest="remote",
        default=None,
        metavar="host:port",
        help="remote host and port to forward to",
    )
    parser.add_option(
        "-K",
        "--key",
        action="store",
        type="string",
        dest="keyfile",
        default=None,
        help="private key file to use for SSH authentication",
    )


    options, args = parser.parse_args()

    print('args {}'.format(args))
    print('options {}'.format(options))

    if len(args) != 0:
        parser.error("Incorrect number of arguments.")
    if options.remote is None:
        parser.error("Remote address required (-r).")

    g_verbose = options.verbose
    remote_host, remote_port = get_host_port(options.remote, SSH_PORT)
    return options, (remote_host, remote_port)


def main():
    options, remote = parse_options()



    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.load_system_host_keys()

    ssh.connect(
        remote[0], remote[1],
        username=options.user, 
        password=options.password,
        key_filename=options.keyfile,
        look_for_keys=True,
    )    

    transport = ssh.get_transport()
    session = transport.open_session()
    session.set_combine_stderr(True)
    session.get_pty(PTY_TERM,PTY_WIDTH, PTY_HEIGHT, PTY_WIDTH_PIXELS, PTY_HEIGHT_PIXELS)
    session.settimeout(10)
    session.exec_command(generateSudoCommand())

    stdin = session.makefile('wb', -1)
    stdout = session.makefile('rb', -1)

    stdin.write(options.password +'\n')
    stdin.flush()

    for line in stdout:
        line = line.decode().strip()
        print('host: %s: %s' % (remote[0], line))

    retcode = stdout.channel.recv_exit_status()
    print('Execution finished with code {}'.format(retcode))




if __name__ == "__main__":
    main()
