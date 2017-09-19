tpm2_rc_decode 1 "SEPTEMBER 2017" tpm2-tools
==================================================

NAME
----

tpm2_rc_decode(1) - Decode TPM2 error codes to human readable format.

SYNOPSIS
--------

`tpm2_rc_decode` [OPTIONS] _RC\_CODE_

DESCRIPTION
-----------

tpm2_rc_decode(1) converts _RC\_CODE_ originating from the SAPI and TCTI into
human readable errors. Analogous to strerror(3), but for the tpm2 stack.

OPTIONS
-------

This tool takes no tool specific options.

[common options](common/options.md)

[common tcti options](common/tcti.md)

EXAMPLES
--------

```
tpm2_rc_decode 0x100
```

RETURNS
-------
0 on success or 1 on failure.

BUGS
----
[Github Issues](https://github.com/01org/tpm2-tools/issues)

HELP
----
See the [Mailing List](https://lists.01.org/mailman/listinfo/tpm2)