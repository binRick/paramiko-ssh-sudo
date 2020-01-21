#!/usr/bin/env python3
from __future__ import print_function
import paramiko, os, json, sys, socket, select, threading, traceback, subprocess, time, getpass, tempfile, pathlib
from optparse import OptionParser

DEBUG_MODE = False
SUDO_ARGS='-k -E -H -u root'
SHELL  = 'sh'
SHELL_ARGS = ""
PTY_TERM = 'xterm'
PTY_WIDTH = 160
PTY_HEIGHT = 24
PTY_WIDTH_PIXELS = 0
PTY_HEIGHT_PIXELS = 0    
PTY_ENV = {'PARAMIKO_SUDO_WRAPPER':'1'}
SOCAT_PATH = '/usr/bin/socat'
SOCAT_TIMEOUT = 1800
TUNNELS = {}
SSH_EXEC_TIMEOUT = 10
HELP = """Paramiko Sudo Forwarded SSH Connection"""


def verbose(s):
    if DEBUG_MODE:
        print(s)

def sudoExecuteLocalPlaybookScriptWrapper(ssh, REMOTE_EXEC_SCRIPT, options, host):
    CMD = '/root/{}'.format(REMOTE_EXEC_SCRIPT)
    START_MS = time.time()
    ExecuteLocal = __sudoCommand(CMD, ssh, options, host)
    ExecuteLocal.daemon = True
    ExecuteLocal.start()
    while True:
        print('       [Playbook Execution Monitor]      stdout: {} lines, {} bytes...{} exit_code'.format(len(ExecuteLocal.lines),len(json.dumps(ExecuteLocal.lines)), ExecuteLocal.exit_code))
        if ExecuteLocal.exit_code:
            DURATION_MS = int(time.time()-START_MS)
            print('       [Playbook Execution Monitor]      Exited {} after {}ms'.format(ExecuteLocal.exit_code,DURATION_MS))
            print('       [Playbook Execution Monitor]        Removing Remote Files....')
            print('       [Playbook Execution Monitor]        Checking Local Files....')
            if ExecuteLocal.exit_code != 0:
                print('       [Playbook Execution Monitor]      FAILED!')
                sys.exit(ExecuteLocal.exit_code)
            else:
                print('       [Playbook Execution Monitor]      OK')
                sys.exit(0)
            
        time.sleep(3.0)

def generateSudoCommand(COMMAND):
    return "command sudo {} {} {} -{}c \"{}\"".format(SUDO_ARGS, generateEnvironmentString(), SHELL, SHELL_ARGS, COMMAND)

def exec_tunnel(ssh,cmd):
    stdin, stdout, stderr = ssh.exec_command(cmd);
    stdout_lines = []
    for line in stdout:
        verbose('[{}] => '.format(cmd) + line.strip('\n'))
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
  def __init__(self, ssh, REMOTE_FORWARDED_FILE, host, options, REMOTE_LISTEN_PORT):
    threading.Thread.__init__(self)
    self.kill_received = False
    self.ssh = ssh
    self.options = options
    self.host = host
    self.REMOTE_LISTEN_PORT = REMOTE_LISTEN_PORT
    self.REMOTE_FORWARDED_FILE = REMOTE_FORWARDED_FILE
  def run(self):
    cmd = '{} -u FILE:{},ignoreeof,seek-end tcp:127.0.0.1:{}'.format(SOCAT_PATH,self.REMOTE_FORWARDED_FILE,self.REMOTE_LISTEN_PORT)
    cmd = generateSudoCommand(cmd)
    while True:
        session = self.ssh.get_transport().open_session()
        session.set_combine_stderr(True)
        session.get_pty(PTY_TERM,PTY_WIDTH, PTY_HEIGHT, PTY_WIDTH_PIXELS, PTY_HEIGHT_PIXELS)
        session.settimeout(SOCAT_TIMEOUT)
        L = EXECUTE_SUDO_COMMAND(cmd,self.ssh,self.options,self.host)
        time.sleep(0.01)

class __localSocat(threading.Thread):
  def __init__(self, LOCAL_LISTEN_PORT, LOCAL_FORWARDED_FILE):
    threading.Thread.__init__(self)
    self.kill_received = False
    self.LOCAL_LISTEN_PORT = LOCAL_LISTEN_PORT
    self.LOCAL_FORWARDED_FILE = LOCAL_FORWARDED_FILE
    self.LOCAL_FORWARDED_OUTPUT = 'CREATE:{},perm=0600'.format(self.LOCAL_FORWARDED_FILE)
    self.basedir = os.path.dirname(self.LOCAL_FORWARDED_FILE)
    pathlib.Path(self.basedir).mkdir(parents=True, exist_ok=True)
    print('__localSocat ok {}'.format(self.basedir))
  def run(self):
    cmd = '{} -u TCP4-LISTEN:{},reuseaddr {}'.format(SOCAT_PATH,self.LOCAL_LISTEN_PORT, self.LOCAL_FORWARDED_OUTPUT)
    cwd = '/'
    env = os.environ.copy()
    while True:
        #print('local socat cmd=\n{}\n'.format(cmd))
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

def EXECUTE_SUDO_COMMAND(cmd,ssh,options,host, lines=[]):
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
            lines.append(line)
            verbose('host: %s: %s' % (host[0], line))

        retcode = stdout.channel.recv_exit_status()
        verbose('Sudo Execution finished with code {}'.format(retcode))
        return retcode
    except Exception as e:
        verbose('Sudo Execution failed')
        verbose(e)
        return None, None


class __sudoCommand(threading.Thread):
  def __init__(self, COMMAND, ssh, options, host):
    threading.Thread.__init__(self)
    self.kill_received = False
    self.ssh = ssh
    self.options  = options
    self.host = host
    self.COMMAND = COMMAND
    self.exit_code = None
    self.lines = []
  def run(self):
    cmd = generateSudoCommand(self.COMMAND)
    self.exit_code = EXECUTE_SUDO_COMMAND(cmd,self.ssh,self.options,self.host, self.lines)


def generateEnvironmentString():
    PTY_ENV_STR = ''
    for k in PTY_ENV.keys():
        PTY_ENV_STR += ' {}={}'.format(k,PTY_ENV[k])
    return PTY_ENV_STR



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
        "-L",
        "--log-files",
        action="store",
        type="string",
        dest="log_files",
        default=None,
        help="log_files",
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
    parser.add_option(
        "-R",
        "--remote-port",
        action="store",
        type="int",
        dest="remote_port",
        default=2251,
        help="remote_port",
    )

    options, args = parser.parse_args()

    verbose('args {}'.format(args))
    verbose('options {}'.format(options))

    if len(args) != 0:
        parser.error("Incorrect number of arguments.")
    if options.remote is None:
        parser.error("Remote address required (-r).")
    if options.log_files is None:
        parser.error("Log Files (F).")
    if options.exec_script is None or not os.path.exists(options.exec_script):
        parser.error("Exec Script (-E).")
    if options.host is None:
        parser.error("Host address required (-h).")

    options.log_files = options.log_files.split(',')
    verbose('options.log_files={}'.format(options.log_files))

    DEBUG_MODE = options.verbose
    host, port = get_host_port(options.host, 22)
    remote_port = get_host_port(options.remote, 22)
    return options, (host,port), (remote_port)

def uploadScript(ssh, REMOTE_EXEC_SCRIPT,options):
    REMOTE_EXEC_SCRIPT_CONTENTS = json.dumps({'abc':123})
    with open(options.exec_script,'r') as f:
        REMOTE_EXEC_SCRIPT_CONTENTS = f.read().strip()
    REMOTE_EXEC_SCRIPT_MODE = 0o700
    with open(REMOTE_EXEC_SCRIPT,'w') as f:
        f.write(REMOTE_EXEC_SCRIPT_CONTENTS)
    with open(REMOTE_EXEC_SCRIPT,'r') as f:
        REMOTE_EXEC_SCRIPT_BYTES = len(f.read())
    sftp = paramiko.SFTPClient.from_transport(ssh.get_transport())
    sftp.put(REMOTE_EXEC_SCRIPT, REMOTE_EXEC_SCRIPT)
    sftp.chmod(REMOTE_EXEC_SCRIPT, REMOTE_EXEC_SCRIPT_MODE)
    sftp.close()
    if os.path.exists(REMOTE_EXEC_SCRIPT):
      os.remove(REMOTE_EXEC_SCRIPT)
    verbose('uploaded {} bytes to remote file {}'.format(REMOTE_EXEC_SCRIPT_BYTES, REMOTE_EXEC_SCRIPT, ))

def sudoLogPathMkdir(ssh, REMOTE_FORWARDED_FILE, options, host):
    CMD = 'command mkdir -p {}'.format(os.path.dirname(REMOTE_FORWARDED_FILE))
    mv = __sudoCommand(CMD, ssh, options, host)
    mv.daemon = False
    mv.start()
    verbose('__sudo mkdir log path finished: {}'.format(CMD))

def sudoMoveScript(ssh, REMOTE_EXEC_SCRIPT, options, host):
    CMD = 'mv -f ~{}/{} /root/.'.format(options.user, REMOTE_EXEC_SCRIPT)
    mv = __sudoCommand(CMD, ssh, options, host)
    mv.daemon = False
    mv.start()
    verbose('__sudo mv finished')

def sudoChmodScript(ssh, REMOTE_EXEC_SCRIPT, MODE, options, host):
    CMD = 'chmod {} /root/{}'.format(MODE, REMOTE_EXEC_SCRIPT)
    mv = __sudoCommand(CMD, ssh, options, host)
    mv.daemon = False
    mv.start()
    verbose('__sudo chmod finished')

def sudoChownScript(ssh, REMOTE_EXEC_SCRIPT, MODE, options, host):
    CMD = 'chown {} /root/{}'.format(MODE, REMOTE_EXEC_SCRIPT)
    mv = __sudoCommand(CMD, ssh, options, host)
    mv.daemon = False
    mv.start()
    verbose('__sudo chown finished')


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
    uploadScript(ssh, REMOTE_EXEC_SCRIPT,options)

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
    for i, REMOTE_FORWARDED_FILE in enumerate(options.log_files):
        localSocat = __localSocat(remote[1]+i, REMOTE_FORWARDED_FILE)
        localSocat.daemon = True
        localSocat.start()
        time.sleep(0.1)

    """   Setup TCP Forwards From Remote to local host """
    for i, REMOTE_FORWARDED_FILE in enumerate(options.log_files):
        REMOTE_PORT = remote[1] + i
        TUNNELS[i] = reverse_forward_tunnel(remote[0], REMOTE_PORT, host[0], options.remote_port + i, ssh.get_transport())
        TUNNELS[i].daemon = True
        TUNNELS[i].start()
        verbose(">> [tunnel #{} ] Started (remote file {} => remote port {})".format(i,REMOTE_FORWARDED_FILE, REMOTE_PORT))
        time.sleep(0.1)

    """   Create Directories to hold remote logs   """
    for i, REMOTE_FORWARDED_FILE in enumerate(options.log_files):
        sudoLogPathMkdir(ssh, REMOTE_FORWARDED_FILE, options, host)

    """   Remote Socat Listener Local File  > Socket """
    for i, REMOTE_FORWARDED_FILE in enumerate(options.log_files):
        verbose("""   Remote Socat Listener Local File  > Socket #{} {}""".format(i,REMOTE_FORWARDED_FILE))
        agent = __socat(ssh, REMOTE_FORWARDED_FILE, host, options, options.remote_port + i)
        agent.daemon = True
        agent.start()
        verbose('remote socat launched...........')
        time.sleep(0.1)

    """   Execute Playbook via sudo in local connection mode  via ssh """
    sudoExecuteLocalPlaybookScriptWrapper(ssh, REMOTE_EXEC_SCRIPT, options, host)

    while True:
        verbose('Checking if execution is complete.....')
        time.sleep(5)


if __name__ == "__main__":
    main()
