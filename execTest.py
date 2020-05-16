#!/usr/bin/env python
import exec_helpers, sys, os, json
from exec_helpers import proc_enums
p = l = print

import traceback


SSH = exec_helpers.SSHClient('vpn299', username="bduser1", password="Q8DHmYMqXAksdf8yh293y97s8d79U")
SSH.sudo_mode = True

command = 'command tail -f /tmp/eee'

"""
SSH = exec_helpers.SSHAuth(
    username='bduser1',  # type: typing.Optional[str]
    password='Q8DHmYMqXAksdf8yh293y97s8d79U',  # type: typing.Optional[str]
    key=None,  # type: typing.Optional[paramiko.RSAKey]
    keys=None,  # type: typing.Optional[typing.Iterable[paramiko.RSAKey]],
    key_filename=None,  # type: typing.Union[typing.List[str], None]
    passphrase=None,  # type: typing.Optional[str]
)
"""

ExecResult = SSH.execute(
    command,
    verbose=True,  # type: bool
    timeout=1 * 60 * 60,
    # Keyword only:
    stdin=None,
    open_stdout=True,
    open_stderr=True,
    get_pty=True,
)


#p(ExecResult)
#p(ExecResult.stdout)
p(ExecResult.cmd)
#p(ExecResult.stdout_str)
p(ExecResult.stdout_brief)
#p(ExecResult.stdout_yaml)
p(ExecResult.timestamp)
p(ExecResult.exit_code)
p(SSH.exists('/etc/passwd'))
p(SSH.exists('/etc/passwd1'))
p(SSH.stat('/etc/passwd'))

#with SSH.sudo(enforce=False):
#    p(SSH.stat('/root/.wow.txt'))
#with SSH.open('/root/.wow.txt', mode='w') as f:
#    f.write('neat\n')




