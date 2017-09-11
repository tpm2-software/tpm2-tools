tpm2_create 8 "AUGUST 2017" Linux "User Manuals"
==================================================

NAME
----

tpm2_create(8) - create an object that can be loaded into a TPM using tpm2_load.
The object will need to be loaded before it may be used.

SYNOPSIS
--------

`tpm2_create` [OPTIONS]

DESCRIPTION
-----------

tpm2_create(8) - create an object that can be loaded into a TPM using tpm2_load.
The object will need to be loaded before it may be used.

OPTIONS
-------

These options for creating the tpm entity:

  * `-H`, `--pparent`=_PARENT\_HANDLE_:
    The handle of the parent object to create this object under.

  * `-c`, `--contextParent`=_PARENT\_CONTEXT\_FILE_:
    The filename for parent context.

  * `-P`, `--pwdp`=_PARENT\_KEY\_PASSWORD_:
    The password for parent key, optional. Passwords should follow the
    "password formatting standards, see section "Password Formatting".

  * `-K`, `--pwdk`=_KEY\_PASSWORD_:
    The password for key, optional. Follows the password formatting of the
    "password for parent key" option: -P.

  * `-g`, `--halg`=_ALGORITHM_:
    The hash algorithm to use. Algorithms should follow the
    " formatting standards, see section "Algorithm Specifiers".
    Also, see section "Supported Hash Algorithms" for a list of supported
    hash algorithms.

  * `-G`, `--kalg`=_KEY\_ALGORITHM_:
    The algorithm associated with this object. It accepts friendly names just
    like -g option.

  * `-A`, `--objectAttributes`=_ATTRIBUTES_:
    The object attributes, optional.

  * `-I`, `--inFile`=_FILE_:
    The data file to be sealed, optional. If file is -, read from stdin.
    When sealing data only the TPM_ALG_KEYEDHASH algorithm is allowed.

  * `-L`, `--policy-file`=_POLICY\_FILE_:
    The input policy file, optional.

  * `-E`, `--enforce-policy`:
    Enforce policy based authorization on the object.

  * `-o`, `--opu`=_OUTPUT\_PUBLIC\_FILE_:
    The output file which contains the public key, optional.

  * `-O`, `--opr`=_OUTPUT\PRIVATE\_FILE_:
    The output file which contains the private key, optional.

* `-S`, `--input-session-handle`=_SESSION\_HANDLE_:
    Optional Input session handle from a policy session for authorization.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[password formatting](common/password.md)

[supported hash algorithms](common/hash.md)

[algorithm specifiers](common/alg.md)

EXAMPLES
--------

```
tpm2_create -H 0x81010001 -P abc123 -K def456 -g 0x000B -G 0x0008 -I data.File -o opu.File
tpm2_create -c parent.context -P abc123 -K def456 -g 0x000B -G 0x0008 -I data.File -o opu.File
tpm2_create -H 0x81010001 -P 123abc -K 456def -X -g 0x000B -G 0x0008 -I data.File -o opu.File
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

AUTHOR
------
William Roberts <william.c.roberts@intel.com>