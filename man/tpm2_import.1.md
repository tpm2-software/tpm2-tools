tpm2_import 1 "SEPTEMBER 2017" tpm2-tools
==================================================

# NAME

tpm2_import(8) - imports an external key into the tpm as a TPM managed key object.

# SYNOPSIS

**tpm2_import** [*OPTIONS*]

# DESCRIPTION

This tool imports an external generated key as TPM managed key object.
It requires that the parent key object be of type RSA key.

# OPTIONS

These options control the key importation process:

  * **-G**, **--import-key-alg**=_ALGORITHM_:
    The algorithm used by the key to be imported. Supports:
    * aes - AES 128 key.
    * rsa - RSA 1024 or 2048 key.

  * **-g**, **--halg**=_ALGORITHM_:
    The hash algorithm for generating the objects name. This is optional
    and defaults to sha256 when not specified. Algorithms should follow the
    "formatting standards", see section "Algorithm Specifiers".
    Also, see section "Supported Hash Algorithms" for a list of supported
    hash algorithms.

  * **-k**, **--input-key-file**=_FILE_:
    Specifies the filename of symmetric key (128 bit data) to be imported. OR,
    Specifies the filename for the RSA2K private key file in PEM and PKCS#1
    format. A typical file is generated with openssl genrsa.

  * **-C**, **--parent-key**=_PARENT\_CONTEXT_:
    Specifies the context object for the parent key. Either a file or a handle number.
    See section "Context Object Format".

  * **-K**, **--parent-key-public**=_FILE_:
    Optional. Specifies the parent key public data file input. This can be read with
    tpm2_readpublic tool. If not specified, the tool invokes a tpm2_readpublic on the parent
    object.

  * **-r**, **--import-key-private**=_FILE_:
    Specifies the file path required to save the encrypted private portion of
    the object imported as key.

  * **-u**, **--import-key-public**=_FILE_:
    Specifies the file path required to save the public portion of the object imported as key

  * **-A**, **--object-attributes**=_ATTRIBUTES_:
    The object attributes, optional.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[context object format](commmon/ctxobj.md)

[algorithm specifiers](common/alg.md)

# EXAMPLES

```
tpm2_import -k sym.key -C 0x81010001 -f parent.pub -q import_key.pub -r import_key.priv

tpm2_import -Q -G rsa -k private.pem -C 0x81010005 -f parent.pub \
-u import_rsa_key.pub -r import_rsa_key.priv
```

# LIMITATIONS
  * The TPM requires that the name algorithm of the child be smaller than the parent.
  * Parents with a SHA1 hash algorithm currently fail. See bug
    [#119](https://github.com/tpm2-software/tpm2-tools/issues/1119) for details.

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
