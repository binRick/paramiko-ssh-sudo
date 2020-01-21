#!/usr/bin/env python3
from __future__ import print_function
import paramiko, os, json, sys, socket, select, threading, traceback, subprocess, time, getpass, tempfile
from optparse import OptionParser


DEBUG_MODE = True

LOCAL_LISTEN_PORT = 49225
REMOTE_LISTEN_PORT = 2251

SUDO_ARGS='-k -H -u root'

SHELL  = 'sh'
SHELL_ARGS = ""

PTY_TERM = 'xterm'
PTY_WIDTH = 160
PTY_HEIGHT = 24
PTY_WIDTH_PIXELS = 0
PTY_HEIGHT_PIXELS = 0    
PTY_ENV = {'abc':'def','wow':123}

SOCAT_PATH = '/usr/bin/socat'
SOCAT_TIMEOUT = 1800

TUNNELS = {}

REMOTE_FORWARDED_FILE = '/var/log/messages'
LOCAL_FILE_FORWARDED_PATH = '/tmp/wow1'
LOCAL_FORWARDED_OUTPUT = 'CREATE:{},perm=0600'.format(LOCAL_FILE_FORWARDED_PATH)

SSH_EXEC_TIMEOUT = 10
DEFAULT_SSH_PORT = 22

DSTAT = 'dstat -alp --top-cpu --top-cputime-avg 1'

HELP = """Paramiko Sudo Forwarded SSH Connection"""

def generateSudoCommand(COMMAND):
    return "command sudo {} {} {} -{}c \"{}\"".format(SUDO_ARGS, generateEnvironmentString(), SHELL, SHELL_ARGS, COMMAND)

def exec_tunnel(ssh,cmd):
    print('et.........')
    stdin, stdout, stderr = ssh.exec_command(cmd);
    stdout_lines = []
    for line in stdout:
        print('[{}] => '.format(cmd) + line.strip('\n'))
        stdout_lines.append(line)
    return stdout_lines

def handler(chan, host, port):
    sock = socket.socket()
    try:
        sock.connect((host, port))
    except Exception as e:
        verbose("Forwarding request to %s:%d failed: %r" % (host, port, e))
        return
    verbose("Connected!  Tunnel open %r -> %r -> %r"% (chan.origin_addr, chan.getpeername(), (host, port)))
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
  def __init__(self,remote_host,remote_port, host, port, transport):
    threading.Thread.__init__(self)
    self.kill_received = False
    self.remote_host = remote_host
    self.remote_port = remote_port
    self.host = host
    self.port = port
    self.transport = transport
  def run(self):
    self.transport.request_port_forward("",self.port)
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
  def __init__(self, ssh, REMOTE_FORWARDED_FILE, host, options):
    threading.Thread.__init__(self)
    self.kill_received = False
    self.ssh = ssh
    self.options = options
    self.host = host
    self.REMOTE_FORWARDED_FILE = REMOTE_FORWARDED_FILE
  def run(self):
    cmd = '{} -u FILE:{},ignoreeof,seek-end tcp:127.0.0.1:{}'.format(SOCAT_PATH,self.REMOTE_FORWARDED_FILE,REMOTE_LISTEN_PORT)
    cmd = generateSudoCommand(cmd)
    while True:
        session = self.ssh.get_transport().open_session()
        session.set_combine_stderr(True)
        session.get_pty(PTY_TERM,PTY_WIDTH, PTY_HEIGHT, PTY_WIDTH_PIXELS, PTY_HEIGHT_PIXELS)
        session.settimeout(SOCAT_TIMEOUT)
        L = EXECUTE_SUDO_COMMAND(cmd,self.ssh,self.options,self.host)
        time.sleep(0.01)

class __localSocat(threading.Thread):
  def __init__(self):
    threading.Thread.__init__(self)
    self.kill_received = False
  def run(self):
    cmd = '{} -u TCP4-LISTEN:{},reuseaddr {}'.format(SOCAT_PATH,LOCAL_LISTEN_PORT, LOCAL_FORWARDED_OUTPUT)
    cwd = '/'
    env = os.environ.copy()
    while True:
        proc = subprocess.Popen(cmd.split(' '),stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd, env=env, shell=False)
        stdout, stderr = proc.communicate()
        exit_code = proc.wait()
        time.sleep(0.01)

class __ls(threading.Thread):
  def __init__(self, ssh):
    threading.Thread.__init__(self)
    self.kill_received = False
    self.ssh = ssh
  def run(self):
    cmd = 'ls /'
    exec_tunnel(self.ssh, cmd)

def EXECUTE_SUDO_COMMAND(cmd,ssh,options,host):
    session = ssh.get_transport().open_session()
    session.set_combine_stderr(True)
    session.get_pty(PTY_TERM,PTY_WIDTH, PTY_HEIGHT, PTY_WIDTH_PIXELS, PTY_HEIGHT_PIXELS)
    session.settimeout(SSH_EXEC_TIMEOUT)
    session.exec_command(cmd)

    stdin = session.makefile('wb', -1)
    stdout = session.makefile('rb', -1)

    stdin.write(options.password +'\n')
    stdin.flush()
    try:
        for line in stdout:
            line = line.decode().strip()
            print('host: %s: %s' % (host[0], line))

        retcode = stdout.channel.recv_exit_status()
        print('Sudo Execution finished with code {}'.format(retcode))
    except Exception as e:
        print('Sudo Execution failed')
        verbose(e)
        pass


class __sudoCommand(threading.Thread):
  def __init__(self, COMMAND, ssh, options, host):
    threading.Thread.__init__(self)
    self.kill_received = False
    self.ssh = ssh
    self.options  = options
    self.host = host
    self.COMMAND = COMMAND
  def run(self):
    cmd = generateSudoCommand(self.COMMAND)

    EXECUTE_SUDO_COMMAND(cmd,self.ssh,self.options,self.host)


def generateEnvironmentString():
    PTY_ENV_STR = ''
    for k in PTY_ENV.keys():
        PTY_ENV_STR += ' {}={}'.format(k,PTY_ENV[k])
    return PTY_ENV_STR


def verbose(s):
    if DEBUG_MODE:
        print(s)

def get_host_port(spec, default_port):
    args = (spec.split(":", 1) + [default_port])[:2]
    args[1] = int(args[1])
    return args[0], args[1]

def parse_options():
    global DEBUG_MODE

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
        "-H",
        "--host",
        action="store",
        type="string",
        dest="host",
        default=None,
        metavar="host:port",
        help="host and port to forward from",
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
    parser.add_option(
        "-E",
        "--exec-script",
        action="store",
        type="string",
        dest="exec_script",
        default=None,
        help="exec_script",
    )

    options, args = parser.parse_args()

    print('args {}'.format(args))
    print('options {}'.format(options))

    if len(args) != 0:
        parser.error("Incorrect number of arguments.")
    if options.remote is None:
        parser.error("Remote address required (-r).")
    if options.host is None:
        parser.error("Host address required (-r).")

    DEBUG_MODE = options.verbose
    host, port = get_host_port(options.host, DEFAULT_SSH_PORT)
    remote_host, remote_port = get_host_port(options.remote, DEFAULT_SSH_PORT)
    return options, (host,port), (remote_host, remote_port)

def uploadScript(ssh, REMOTE_EXEC_SCRIPT):
    REMOTE_EXEC_SCRIPT_CONTENTS = json.dumps({'abc':123})
    REMOTE_EXEC_SCRIPT_MODE = 0o700
    with open(REMOTE_EXEC_SCRIPT,'w') as f:
        f.write(REMOTE_EXEC_SCRIPT)
    with open(REMOTE_EXEC_SCRIPT,'r') as f:
        REMOTE_EXEC_SCRIPT_BYTES = len(f.read())
    sftp = paramiko.SFTPClient.from_transport(ssh.get_transport())
    sftp.put(REMOTE_EXEC_SCRIPT, REMOTE_EXEC_SCRIPT)
    sftp.chmod(REMOTE_EXEC_SCRIPT, REMOTE_EXEC_SCRIPT_MODE)
    sftp.close()
    if os.path.exists(REMOTE_EXEC_SCRIPT):
      os.remove(REMOTE_EXEC_SCRIPT)
    print('uploaded {} bytes to remote file {}'.format(REMOTE_EXEC_SCRIPT_BYTES, REMOTE_EXEC_SCRIPT, ))

def sudoMoveScript(ssh, REMOTE_EXEC_SCRIPT, options, host):
    CMD = 'mv -f ~{}/{} /root/.'.format(options.user, REMOTE_EXEC_SCRIPT)
    mv = __sudoCommand(CMD, ssh, options, host)
    mv.daemon = False
    mv.start()
    print('__sudo mv finished')

def sudoChmodScript(ssh, REMOTE_EXEC_SCRIPT, MODE, options, host):
    CMD = 'chmod {} /root/{}'.format(MODE, REMOTE_EXEC_SCRIPT)
    mv = __sudoCommand(CMD, ssh, options, host)
    mv.daemon = False
    mv.start()
    print('__sudo chmod finished')

def sudoChownScript(ssh, REMOTE_EXEC_SCRIPT, MODE, options, host):
    CMD = 'chown {} /root/{}'.format(MODE, REMOTE_EXEC_SCRIPT)
    mv = __sudoCommand(CMD, ssh, options, host)
    mv.daemon = False
    mv.start()
    print('__sudo chown finished')


def main():
    options, host, remote = parse_options()
    tf = tempfile.NamedTemporaryFile(delete=False)
    REMOTE_EXEC_SCRIPT = "{}".format(os.path.basename(tf.name))
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.load_system_host_keys()

    ssh.connect(
        host[0], host[1],
        username=options.user, 
        password=options.password,
        key_filename=options.keyfile,
        look_for_keys=True,
    )    

    """   Upload Script to non root user home dir   """
    uploadScript(ssh, REMOTE_EXEC_SCRIPT)

    time.sleep(0.1)
    """   Move to root dir   """
    sudoMoveScript(ssh, REMOTE_EXEC_SCRIPT, options, host)

    time.sleep(0.1)
    """   Chmod root Script   """
    sudoChmodScript(ssh, REMOTE_EXEC_SCRIPT, '0700', options, host)

    time.sleep(0.1)
    """   Chown root Script   """
    sudoChownScript(ssh, REMOTE_EXEC_SCRIPT, 'root:root', options, host)


    """   Local Socat Listener Local Socket  > File  """
    localSocat = __localSocat()
    localSocat.daemon = True
    localSocat.start()


    """   Setup TCP Tunnel   """
    TUNNELS['tunnel1'] = reverse_forward_tunnel(remote[0], remote[1], host[0], REMOTE_LISTEN_PORT, ssh.get_transport())
    TUNNELS['tunnel1'].daemon = True
    TUNNELS['tunnel1'].start()
    print(">> [tunnel1 Tunnel] Started")


    """   Remote Socat Listener Local File  > Socket """
    agent = __socat(ssh, REMOTE_FORWARDED_FILE, host, options)
    agent.daemon = True
    agent.start()
    print('remote socat launched...........')


    while True:
        print('Checking if execution is complete.....')
        time.sleep(5)


if __name__ == "__main__":
    main()
