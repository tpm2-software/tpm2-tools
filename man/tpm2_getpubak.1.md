tpm2_getpubak 1 "SEPTEMBER 2017" tpm2-tools
==================================================

NAME
----

tpm2_getpubak(1) - Generate attestation key with given algorithm under the
endorsement hierarchy.

SYNOPSIS
--------

`tpm2_getpubak` [OPTIONS]

DESCRIPTION
-----------

tpm2_getpubak(1) - Generate attestation key with given algorithm under
endorsement hierarchy, make it persistent with given ak handle, and
return pub AK and AK name. If any passwd option is missing, assume NULL.

OPTIONS
-------

  * `-e`, `--endorsePasswd`=_ENDORSE\_PASSWORD_:
    Specifies current endorsement password, defaults to NULL.
    Passwords should follow the "password formatting standards, see section
    "Password Formatting".

  * `-P`, `--akPasswd`=_AK\_PASSWORD_
    Specifies the AK password when created, defaults to NULL.
    Same formatting as the endorse password value or -e option.

  * `-o`, `--ownerPasswd`=_OWNER\_PASSWORD_
    Specifies the current owner password, defaults to NULL.
    Same formatting as the endorse password value or -e option.

  * `-E`, `--ekHandle`=_EK\_HANDLE_:
    Specifies the handle used to make EK persistent.

  * `-k`, `--akHandle`=_AK\_HANDLE_:
    Specifies the handle used to make AK persistent.

  * `-g`, `--alg`=_ALGORITHM_:
    Specifies the algorithm type of AK. Algorithms should follow the
    " formatting standards, see section "Algorithm Specifiers".
    See section "Supported Public Object Algorithms" for a list of supported
    object algorithms.

  * `-g`, `--alg`=_ALGORITHM_:
    Like -g, but specifies the algorithm of sign.
    See section "Supported Signing Algorithms" for details.

  * `-f`, `--file`=_FILE_:
    Specifies the file used to save the public portion of AK. This will be a
    binary data structure corresponding to the TPM2B_PUBLIC struct in the
    specification.

  * `-n`, `--akName`=_NAME_:
    Specifies the file used to save the ak name.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[password formatting](common/password.md)

[supported signing algorithms](common/sign-alg.md)

[supported public object algorithms](common/object-alg.md)

[algorithm specifiers](common/alg.md)

EXAMPLES
--------
```
tpm2_getpubak -e abc123 -P abc123 -o passwd -E 0x81010001 -k 0x81010002 -f ./ak.pub -n ./ak.name
tpm2_getpubak -e 1a1b1c -P 123abc -o 1a1b1c -X -E 0x81010001 -k 0x81010002 -f ./ak.pub -n ./ak.name
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
