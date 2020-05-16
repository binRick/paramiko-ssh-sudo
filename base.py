#!/usr/bin/env python3
import exec_helpers
from exec_helpers import proc_enums

print('....................')



client = exec_helpers.SSHClient(host, username="username", password="password")

auth = exec_helpers.SSHAuth(
    username='username',  # type: typing.Optional[str]
    password='password',  # type: typing.Optional[str]
    key=None,  # type: typing.Optional[paramiko.RSAKey]
    keys=None,  # type: typing.Optional[typing.Iterable[paramiko.RSAKey]],
    key_filename=None,  # type: typing.Union[typing.List[str], None]
    passphrase=None,  # type: typing.Optional[str]
)

result: ExecResult = helper.execute(
    command,  # type: str
    verbose=False,  # type: bool
    timeout=1 * 60 * 60,  # type: typing.Union[int, float, None]
    # Keyword only:
    log_mask_re=None,  # type: typing.Optional[str]
    stdin=None,  # type: typing.Union[bytes, str, bytearray, None]
    open_stdout=True,  # type: bool
    open_stderr=True,  # type: bool
    **kwargs
)

result: ExecResult = helper.check_call(
    command,  # type: str
    verbose=False,  # type: bool
    timeout=1 * 60 * 60,  # type: type: typing.Union[int, float, None]
    error_info=None,  # type: typing.Optional[str]
    expected=(0,),  # type: typing.Iterable[typing.Union[int, ExitCodes]]
    raise_on_err=True,  # type: bool
    # Keyword only:
    log_mask_re=None,  # type: typing.Optional[str]
    stdin=None,  # type: typing.Union[bytes, str, bytearray, None]
    open_stdout=True,  # type: bool
    open_stderr=True,  # type: bool
    exception_class=CalledProcessError,  # typing.Type[CalledProcessError]
    **kwargs
)

result: ExecResult = helper.check_stderr(
    command,  # type: str
    verbose=False,  # type: bool
    timeout=1 * 60 * 60,  # type: type: typing.Union[int, float, None]
    error_info=None,  # type: typing.Optional[str]
    raise_on_err=True,  # type: bool
    # Keyword only:
    expected=(0,),  # typing.Iterable[typing.Union[int, ExitCodes]]
    log_mask_re=None,  # type: typing.Optional[str]
    stdin=None,  # type: typing.Union[bytes, str, bytearray, None]
    open_stdout=True,  # type: bool
    open_stderr=True,  # type: bool
    exception_class=CalledProcessError,  # typing.Type[CalledProcessError]
)

result: ExecResult = helper(  # Lazy way: instances are callable and uses `execute`.
    command,  # type: str
    verbose=False,  # type: bool
    timeout=1 * 60 * 60,  # type: typing.Union[int, float, None]
    # Keyword only:
    log_mask_re=None,  # type: typing.Optional[str]
    stdin=None,  # type: typing.Union[bytes, str, bytearray, None]
    open_stdout=True,  # type: bool
    open_stderr=True,  # type: bool
    **kwargs
)

result: ExecResult = helper.execute(
    command="AUTH='top_secret_key'; run command",  # type: str
    verbose=False,  # type: bool
    timeout=1 * 60 * 60,  # type: typing.Optional[int]
    log_mask_re=r"AUTH\s*=\s*'(\w+)'"  # type: typing.Optional[str]
)



results: Dict[Tuple[str, int], ExecResult] = SSHClient.execute_together(
    remotes,  # type: typing.Iterable[SSHClient]
    command,  # type: str
    timeout=1 * 60 * 60,  # type: type: typing.Union[int, float, None]
    expected=(0,),  # type: typing.Iterable[typing.Union[int, ExitCodes]]
    raise_on_err=True,  # type: bool
    # Keyword only:
    stdin=None,  # type: typing.Union[bytes, str, bytearray, None]
    open_stdout=True,  # type: bool
    open_stderr=True,  # type: bool
    log_mask_re=None,  # type: typing.Optional[str]
    exception_class=ParallelCallProcessError  # typing.Type[ParallelCallProcessError]
)
results  # type: typing.Dict[typing.Tuple[str, int], exec_result.ExecResult]



conn: SSHClient = client.proxy_to(host, username="username", password="password")

result: ExecResult = client.execute_through_host(
    hostname,  # type: str
    command,  # type: str
    # Keyword only:
    auth=None,  # type: typing.Optional[SSHAuth]
    target_port=22,  # type: int
    timeout=1 * 60 * 60,  # type: type: typing.Union[int, float, None]
    verbose=False,  # type: bool
    stdin=None,  # type: typing.Union[bytes, str, bytearray, None]
    open_stdout=True,  # type: bool
    open_stderr=True,  # type: bool
    log_mask_re=None,  # type: typing.Optional[str]
    get_pty=False,  # type: bool
    width=80,  # type: int
    height=24  # type: int
)


with client.sudo(enforce=True):


with client.sudo(enforce=False):


with client.open(path, mode='r') as f:


conn.exists('/etc/passwd')

conn.stat('/etc/passwd')

conn.isfile('/etc/passwd')

conn.isdir('/etc/passwd')


async with helper:
  result: ExecResult = await helper.execute(
      command,  # type: str
      verbose=False,  # type: bool
      timeout=1 * 60 * 60,  # type: typing.Union[int, float, None]
      **kwargs
  )


