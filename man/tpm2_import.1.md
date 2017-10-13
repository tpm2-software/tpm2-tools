tpm2_import 1 "SEPTEMBER 2017" tpm2-tools
==================================================

NAME
----

tpm2_import(8) - imports an external key (AES-128) into the tpm as a TPM managed key object.

SYNOPSIS
--------

`tpm2_import` [OPTIONS]

DESCRIPTION
-----------
This tool imports an external key (Symmetric AES-128) as TPM managed key object.
It requires the parent handle be persistent and an object of type RSA key.

OPTIONS
-------

These options control the key importation process:

  * `-k`, `--input-key-file`=_FILE_:
    Specifies the filename of symmetric key (128 bit data) to be imported.

  * `-H`, `--parent-key-handle`=_HANDLE_:
    Specifies the persistent parent key handle.

  * `-f`, `--parent-key-public`=_FILE_:
    Specifies the parent key public data file input. This can be read with
    tpm2_readpublic tool.

  * `-r`, `--import-key-private`=_FILE_:
    Specifies the file path required to save the encrypted private portion of
    the object imported as key.

  * `-q`, `--import-key-public`=_FILE_:
    Specifies the file path required to save the public portion of the object imported as key

[common options](common/options.md)

[common tcti options](common/tcti.md)

EXAMPLES
--------

tpm2_import -k sym.key -H 0x81010001 -f parent.pub -q import_key.pub -r import_key.priv

RETURNS
-------
0 on success or 1 on failure.

BUGS
----
[Github Issues](https://github.com/01org/tpm2-tools/issues)

HELP
----
See the [Mailing List](https://lists.01.org/mailman/listinfo/tpm2)

