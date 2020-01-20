#!/usr/bin/env python3
from __future__ import print_function
import paramiko, os, json, sys, socket, select, threading, traceback, subprocess, time, getpass
from optparse import OptionParser

PTY_ENV = {'abc':'def','wow':123}

REMOTE_FORWARDED_PORT = 2233
FORWARDED_PORT_DEST = 49552
PTY_TERM = 'xterm'
PTY_WIDTH = 160
PTY_HEIGHT = 24
PTY_WIDTH_PIXELS = 0
PTY_HEIGHT_PIXELS = 0    
EXEC_TIMEOUT = 10
TUNNELS = {}

EXEC_TIMEOUT = 10
DSTAT = 'dstat -alp --top-cpu --top-cputime-avg 1'
SSH_PORT = 22
HELP = """\
Paramiko SSH Test
"""

COMMANDS = ['id','ls /','find /']
COMMANDS = ['id','ls /','tail -f /var/log/messages']
COMMANDS = ['id','ls /','journalctl -f']
COMMANDS = ['id','ls /','env']
COMMANDS = ['id','ls /']
COMMANDS = ['id','ls /',DSTAT]

SH_ARGS = "i"
#COMMAND = ' && '.join(COMMANDS)
SUDO_ARGS='-k -H -u root'
g_verbose = True

def generateSudoCommand(COMMAND):
    return "command sudo {} {} sh -{}c \"{}\"".format(SUDO_ARGS, generateEnvironmentString(), SH_ARGS, COMMAND)

def exec_tunnel(ssh,cmd):
    print('et.........')
    stdin, stdout, stderr = ssh.exec_command(cmd);
    for line in stdout:
        print('[{}] => '.format(cmd) + line.strip('\n'))

def handler(chan, host, port):
    sock = socket.socket()
    try:
        sock.connect((host, port))
    except Exception as e:
        verbose("Forwarding request to %s:%d failed: %r" % (host, port, e))
        return

    verbose(
        "Connected!  Tunnel open %r -> %r -> %r"
        % (chan.origin_addr, chan.getpeername(), (host, port))
    )
    while True:
        r, w, x = select.select([sock, chan], [], [])
        if sock in r:
            data = sock.recv(1024)
            if len(data) == 0:
                break
            chan.send(data)
        if chan in r:
            data = chan.recv(1024)
            if len(data) == 0:
                break
            sock.send(data)
    chan.close()
    sock.close()
    verbose("Tunnel closed from %r" % (chan.origin_addr,))


class reverse_forward_tunnel(threading.Thread):
  def __init__(self,server_port, remote_host, remote_port, transport):
    threading.Thread.__init__(self)
    self.kill_received = False
    self.server_port = server_port
    self.remote_host = remote_host
    self.remote_port = remote_port
    self.transport = transport
  def run(self):
    self.transport.request_port_forward("", self.server_port)
    while True:
        chan = self.transport.accept(1000)
        if chan is None:
            continue
        thr = threading.Thread(
            target=handler, args=(chan, self.remote_host, self.remote_port)
        )
        thr.setDaemon(True)
        thr.start()


class __socat(threading.Thread):
  def __init__(self, ssh, SOCAT_FILE):
    threading.Thread.__init__(self)
    self.kill_received = False
    self.ssh = ssh
    self.SOCAT_FILE = SOCAT_FILE
  def run(self):
    cmd = 'socat -u FILE:{},ignoreeof,seek-end tcp:127.0.0.1:2233'.format(self.SOCAT_FILE)
    time.sleep(2.0)


    session = self.ssh.get_transport().open_session()
    session.set_combine_stderr(True)
    session.get_pty(PTY_TERM,PTY_WIDTH, PTY_HEIGHT, PTY_WIDTH_PIXELS, PTY_HEIGHT_PIXELS)
    session.settimeout(EXEC_TIMEOUT)
 #   session.exec_command(generateSudoCommand(cmd))
    exec_tunnel(self.ssh, generateSudoCommand(cmd))

#    exec_tunnel(self.ssh, cmd)


class __localSocat(threading.Thread):
  def __init__(self):
    threading.Thread.__init__(self)
    self.kill_received = False
  def run(self):
    cmd = 'socat -u TCP4-LISTEN:49225,reuseaddr CREATE:/tmp/6c1bf75e-0733-4738-b552-a1118e12c61e/audit.json,perm=0640'
    cwd = '/'
    env = os.environ.copy()
    time.sleep(2.0)
    proc = subprocess.Popen(cmd.split(' '),stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd, env=env, shell=False)
    stdout, stderr = proc.communicate()
    exit_code = proc.wait()

class __ls(threading.Thread):
  def __init__(self, ssh):
    threading.Thread.__init__(self)
    self.kill_received = False
    self.ssh = ssh
  def run(self):
    cmd = 'ls /'
    exec_tunnel(self.ssh, cmd)





def generateEnvironmentString():
    PTY_ENV_STR = ''
    for k in PTY_ENV.keys():
        PTY_ENV_STR += ' {}={}'.format(k,PTY_ENV[k])
    return PTY_ENV_STR


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

    ls = __ls(ssh)
    ls.daemon = False
    ls.start()

    localSocat = __localSocat()
    localSocat.daemon = True
    localSocat.start()


    SOCAT_FILE = '/var/log/messages'
    agent = __socat(ssh, SOCAT_FILE)
    agent.daemon = True
    agent.start()


    TUNNELS['json_audit'] = reverse_forward_tunnel(REMOTE_FORWARDED_PORT, remote[0], FORWARDED_PORT_DEST, ssh.get_transport())
    TUNNELS['json_audit'].daemon = True
    TUNNELS['json_audit'].start()
    print(">> [json_audit Tunnel] Started")

    #reverse_forward_tunnel(REMOTE_FORWARDED_PORT, remote[0], FORWARDED_PORT_DEST, ssh.get_transport())



    session = ssh.get_transport().open_session()
    session.set_combine_stderr(True)
    session.get_pty(PTY_TERM,PTY_WIDTH, PTY_HEIGHT, PTY_WIDTH_PIXELS, PTY_HEIGHT_PIXELS)
    session.settimeout(EXEC_TIMEOUT)
    session.exec_command(generateSudoCommand(DSTAT))

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
