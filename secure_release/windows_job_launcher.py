"""Trusted isolated launcher: source commands wait for parent Job assignment.

Executed as an absolute script by the official Python runtime with -I -S.
The private one-byte stdin channel conveys authorization only, never keys or
environment values. Approved source commands themselves always get null stdin.
No exception, command line or environment is printed by this launcher.
"""
import subprocess
import sys


def main():
    if sys.stdin.buffer.read(1) != b"G" or len(sys.argv) < 2:
        return 125
    child = subprocess.Popen(sys.argv[1:], stdin=subprocess.DEVNULL, close_fds=True)
    return child.wait()


if __name__ == "__main__":
    try:
        code = main()
    except BaseException:
        code = 125
    raise SystemExit(code)
