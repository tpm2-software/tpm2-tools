tpm2_load 1 "SEPTEMBER 2017" tpm2-tools
==================================================

NAME
----

tpm2_load(1) - Load an object into the TPM.

SYNOPSIS
--------

`tpm2_load` [OPTIONS]

DESCRIPTION
-----------

tpm2_load(1) - Load both the private and public portions of an object
into the TPM.

OPTIONS
-----------

  * `-H`, `--parent`=_PARENT\_HANDLE_:
    The handle of the parent object. Either this option or `-c` must be used.

  * `-c`, `--contextParent`=_PARENT\_CONTEXT\_FILE_:
    The filename for parent context.

  * `-P`, `--pwdp`=_PARENT\_KEY\_PASSWORD_:
    The password for parent key, optional. Passwords should follow the
    "password formatting standards, see section "Password Formatting".

  * `-u`, `--pubfile`=_PUBLIC\_OBJECT\_DATA\_FILE_:
    A file containing the public portion of the object.

  * `-r`, `--privfile`=_PRIVATE\_OBJECT\_DATA\_FILE_:
    A file containing the sensitive portion of the object.

  * `-n`, `--name`=_NAME\_DATA\_FILE_:
    An optional file to save the name structure of the object.

  * `-C`, `--name`=_CONTEXT\_FILE_:
    An optional file to save the object context to.

  * `-C`, `--name`=_CONTEXT\_FILE_:
    An optional file to save the object context to.

  * `-S`, `--input-session-handle`=_SESSION\_HANDLE_:
    Optional Input session handle from a policy session for authorization.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[password formatting](common/password.md)


EXAMPLES
--------

```
tpm2_load  -H 0x80000000 -P abc123 -u <pubKeyFileName> -r <privKeyFileName> -n <outPutFileName>
tpm2_load  -c parent.context -P abc123 -u <pubKeyFileName> -r <privKeyFileName> -n <outPutFileName> -C object.context
tpm2_load  -H 0x80000000 -P "hex:123abc" -u <pubKeyFileName> -r <privKeyFileName> -n <outPutFileName>

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