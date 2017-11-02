#!/usr/bin/env python

from subprocess import call
import cmd, sys


class TPM2Shell(cmd.Cmd, object):
    prompt = 'tpm2 > '
    file = None

    def __init__(self, *args, **kwargs):

        _last_rc = 0
        super(TPM2Shell, self).__init__(*args, **kwargs)

    def default(self, line):

        if line == 'EOF':
            return True

        chunks = line.split()
        orig = chunks[0]
        cmd = "tpm2_" + chunks[0]
        chunks[0] = cmd
        try:
            self._last_rc = call(chunks)
        except OSError:
            try:
                chunks[0] = orig
                self._last_rc = call(chunks)
            except OSError as e:
                self._last_rc = e.errno
                sys.stderr.write("Unknown command: %s\n" % orig)


if __name__ == '__main__':

    s = TPM2Shell()
    if len(sys.argv) > 1:
        cmd = ' '.join(sys.argv[1:])
        s.onecmd(cmd)
        sys.exit(s._last_rc)
    else:
        s.cmdloop()
        sys.exit(0)
