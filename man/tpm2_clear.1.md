tpm2_clear 1 "DECEMBER 2017" tpm2-tools
==================================================

NAME
----

tpm2_clear(1) - send a clear command to the TPM.

SYNOPSIS
--------

`tpm2_clear` [OPTIONS]

DESCRIPTION
-----------

tpm2_clear(1) - send a clear command to the TPM, i.e. clear the 3 authorization
values. If the lockout password option is missing, assume NULL.

OPTIONS
-------

  * **-p**, **--platform**:
    specifies the tool should operate on the platform hierarchy. By default
    it operates on the lockout hierarchy.

  * **-L**, **--lockout-passwd**=_LOCKOUT\_PASSWORD_:
    The lockout authorization value.

    Passwords should follow the password formatting standards, see section
    "Password Formatting".

[common options](common/options.md)

[common tcti options](common/tcti.md)

[password formatting](common/password.md)

EXAMPLES
--------

Set owner, endorsement and lockout authorizations to an empty auth value:

```
tpm2_clear -L oldlockoutpasswd
```

Clear the authorizations values on the platform hierarchy:

```
tpm2_clear -p
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
