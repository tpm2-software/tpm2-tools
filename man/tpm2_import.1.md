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

  * `-G`, **--import-key-alg**=_ALGORITHM_:
    The hash algorithm to use. Algorithms should follow the
    " formatting standards, see section "Algorithm Specifiers".
    Also, see section "Supported Hash Algorithms" for a list of supported
    hash algorithms.

  * `-K`, **--input-public-key-file**=_FILE_:
    Specifies the file name for the RSA2K modulus when importing RSA2K key.

  * `-k`, `--input-key-file`=_FILE_:
    Specifies the filename of symmetric key (128 bit data) to be imported. OR,
    Specifies the filename for the RSA2K prime (P) value.

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

  * **-A**, **--object-attributes**=_ATTRIBUTES_:
    The object attributes, optional.

[common options](common/options.md)

[common tcti options](common/tcti.md)

EXAMPLES
--------

tpm2_import -k sym.key -H 0x81010001 -f parent.pub -q import_key.pub -r import_key.priv

tpm2_import -Q -G rsa -K rsa2k_modulus.bin -k rsa2k_P.bin -H 0x81010005 -f parent.pub \
-q import_rsa_key.pub -r import_rsa_key.priv

RETURNS
-------
0 on success or 1 on failure.

[footer](common/footer.md)
