#!/usr/bin/env python3

#
# This TCTI is designed to use with the subprocess TCTI and echo the contents
# of arg1, formatted as a hex string, as a response to a single TPM command.
#
# Example"
# ./tools/tpm2 getcap --tcti='cmd:./test/scripts/echo_tcti.py 8001000000170000000001000001000000000100000003' -i vendor
# 0000000100000003
#

import binascii
import codecs
import io
import sys


def from_bytes(b):
    # python2 and 3 compat int.from_bytes(byte_order='big')
    return int(codecs.encode(b, "hex"), 16)


class TPMCommand(object):
    def __init__(self, data):
        self._data = data

    @property
    def size(self, data_only=False):
        x = from_bytes(self._data[2:6])
        return x if data_only == False else x - 10

    @property
    def tag(self):
        return from_bytes(self._data[0:2])

    @property
    def cc(self):
        return from_bytes(self._data[6:10])

    @property
    def data(self):
        return self._data[10:]

    @property
    def header(self):
        return self._data[:10]


def read_command(stdin):
    # TPM Command Header
    # TAG  UINT16 0:2
    # SIZE UINT32 2:6
    # CC   UINT32 6:10
    # DATA
    header = stdin.read(10)
    # Check for EOF
    if len(header) == 0:
        return None
    elif len(header) < 10:
        raise RuntimeError("Length of header invalid, got: %u" % len(header))
    size = from_bytes(header[2:6])
    data = stdin.read(size - 10)
    return TPMCommand(header + data)


def write_response(data):
    with io.open(sys.stdout.fileno(), "wb", closefd=False) as stdout:
        bdata = binascii.unhexlify(data)
        stdout.write(bdata)
        stdout.flush()


def main():

    if len(sys.argv) < 2:
        sys.stderr.write(
            "Expected one argument of a hex string to use as a TPM response buffer.\n"
        )
        sys.exit(1)

    with io.open(sys.stdin.fileno(), "rb", closefd=False) as stdin:
        c = read_command(stdin)
        if c is None:
            sys.exit
        write_response(sys.argv[1])


if __name__ == "__main__":
    main()
