tpm2_clear 1 "DECEMBER 2017" tpm2-tools
==================================================

NAME
----

tpm2_clear(1) - Send a clear command to the TPM.

SYNOPSIS
--------

`tpm2_clear` [OPTIONS]

DESCRIPTION
-----------

tpm2_clear(1) Send a `TPM2_Clear` command with `TPM2_RH_PLATFORM`.

OPTIONS
-------

[common options](common/options.md)

[common tcti options](common/tcti.md)

EXAMPLES
--------

```
tpm2_clear
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
