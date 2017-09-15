tpm2_nvreadlock 1 "SEPTEMBER 2017" tpm2-tools
==================================================

NAME
----

tpm2_nvreadlock(1) - lock the Non-Volatile (NV) index for further reads.

SYNOPSIS
--------

`tpm2_nvreadlock` [OPTIONS]

DESCRIPTION
-----------

tpm2_nvreadlock(1) - lock the Non-Volatile (NV) index for further reads. The index
is released on subsequent restart of the machine.

OPTIONS
-------

  * `-x`, `--index`=_NV\_INDEX_:
    Specifies the index to define the space at.

  * `-a`, `--authHandle`=_SECRET\_DATA\_FILE_:
    specifies the handle used to authorize:
    * `0x40000001` for `TPM_RH_OWNER`
    * `0x4000000C` for `TPM_RH_PLATFORM`

  * `-P`, `--handlePasswd`=_HANDLE\_PASSWORD_:
    specifies the password of authHandle. Passwords should follow the
    "password formatting standards, see section "Password Formatting".

  * `-S`, `--input-session-handle`=_SIZE_:
    Optional Input session handle from a policy session for authorization.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[password formatting](common/password.md)

EXAMPLES
--------

To lock an index protected by a password:

```
tpm2_nvreadlock -x 0x1500016 -a 0x40000001 -P passwd
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