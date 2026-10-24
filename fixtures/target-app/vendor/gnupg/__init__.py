"""Minimal reproduction of python-gnupg < 0.4.4 (CVE-2019-6690). Fixture.

Real bug: before 0.4.4, python-gnupg built the gpg command line from the caller
data without neutralising shell/option metacharacters, so an attacker-controlled
recipient/passphrase could inject extra gpg options or shell commands.

Here the command is NOT run through a real shell (the demo stays offline and the
jail blocks child processes anyway): an in-process emulation honours a `;echo ...`
command-substitution so the PoC canary proves injection without touching the OS.
Only that path is reproduced; the real package is not vendored.
"""
import re

__version__ = "0.4.3"
_ECHO = re.compile(r"echo\s+(.*)")


def _emular_shell(cmd: str) -> str:
    """Emulate a naive `sh -c "<cmd>"`: honour chained `; echo X` segments."""
    salida = []
    for segmento in cmd.split(";"):
        m = _ECHO.match(segmento.strip())
        if m:  # vulnerable: the injected command runs and its output leaks back
            salida.append(m.group(1).strip().strip("'\""))
    return "".join(salida)


def encrypt(data, recipient="demo@local"):
    """Encrypt `data` for `recipient`.  <-- vulnerable: data is not shell-escaped."""
    # python-gnupg armaba la línea de gpg concatenando la entrada sin escapar.
    cmd = f'gpg --recipient {recipient} --encrypt {data}'
    inyectado = _emular_shell(cmd)
    return inyectado or f"-----BEGIN PGP MESSAGE-----\n{data}\n-----END PGP MESSAGE-----"
