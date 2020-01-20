#!/usr/bin/env python3
import paramiko, os, json, sys, socket, select, threading, traceback, subprocess, time, getpass
from optparse import OptionParser


SSH_PORT = 22
HELP = """\
Paramiko SSH Test
"""
COMMAND = 'id && ls /'
SUDO_ARGS='-k -H -u root'
SUDO_CMD = "command sudo {} sh -c \"{}\"".format(SUDO_ARGS, COMMAND)
g_verbose = True

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
    )    

    transport = ssh.get_transport()

    session = transport.open_session()
    session.set_combine_stderr(True)
    session.get_pty()
    session.exec_command(SUDO_CMD)

    stdin = session.makefile('wb', -1)
    stdout = session.makefile('rb', -1)

    stdin.write(options.password +'\n')
    stdin.flush()

    for line in stdout.read().splitlines():        
        line = line.decode().strip()
        print('host: %s: %s' % (remote[0], line))




if __name__ == "__main__":
    main()
