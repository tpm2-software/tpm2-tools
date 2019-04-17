% tpm2_import(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_import**(1) - Imports an external key into the tpm as a TPM managed key object.

# SYNOPSIS

**tpm2_import** [*OPTIONS*]

# DESCRIPTION

**tpm2_import**(1) - Imports an external generated key as TPM managed key object.
It requires that the parent key object be a RSA key.

# OPTIONS

These options control the key importation process:

  * **-G**, **--algorithm**=_ALGORITHM_:

    The algorithm used by the key to be imported. Supports:
    * **aes** - AES 128, 192 or 256 key.
    * **rsa** - RSA 1024 or 2048 key.
    * **ecc** - ECC NIST P192, P224, P256, P384 or P521 public and private key.

  * **-g**, **--halg**=_ALGORITHM_:

    The hash algorithm for generating the objects name. This is optional
    and defaults to **sha256** when not specified. Algorithms should follow the
    "formatting standards", see section "Algorithm Specifiers".
    Also, see section "Supported Hash Algorithms" for a list of supported
    hash algorithms.

  * **-i**, **--infile**=_FILE_:

    Specifies the filename of symmetric key (128 bit data) to be imported. OR,
    Specifies the filename for the RSA2048 private key file in PEM and PKCS#1
    format. A typical file is generated with `openssl genrsa`.

  * **-C**, **--parent-key**=_PARENT\_CONTEXT_:

    Specifies the context object for the parent key. Either a file or a handle number.
    See section "Context Object Format". The parent key **MUST** be an *RSA* key with an
    symmetric cipher of *aes128cfb*.

  * **-K**, **--parent-pubkey**=_FILE_:

    Optional. Specifies the parent key public data file input. This can be read with
    **tpm2_readpublic**(1) tool. If not specified, the tool invokes a tpm2_readpublic on the parent
    object.

  * **-r**, **--privfile**=_FILE_:

    Specifies the file path required to save the encrypted private portion of
    the object imported as key.

  * **-u**, **--pubfile**=_FILE_:

    Specifies the file path required to save the public portion of the object imported as key

  * **-b**, **--object-attributes**=_ATTRIBUTES_:

    The object attributes, optional.

  * **-P**, **--auth-parent**=_PARENT\_KEY\_AUTH_:

    The authorization value for using the parent key, optional.
    Authorization values should follow the "authorization formatting standards",
    see section "Authorization Formatting".

  * **-p**, **--auth-key**=_KEY\_AUTH_:

    The authorization value for the key, optional.
    Follows the authorization formatting of the
    "password for parent key" option: **-P**.

  * **--passin**=_OSSL\_PEM\_FILE\_PASSWORD_

    An optional password for an Open SSL (OSSL) provided input file. It mirrors the -passin option of
    OSSL and is known to support the pass, file, env, fd and plain password formats of openssl.
    (see *man(1) openssl*) for more.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[context object format](common/ctxobj.md)

[algorithm specifiers](common/alg.md)

# EXAMPLES

## To import a key, one needs to have a parent key
```
tpm2_createprimary -Grsa2048:aes128cfb -a o -o parent.ctx
```

Create your key and and import it. If you already have a key, just use that
and skip creating it.

## Import an AES 128 key
```
dd if=/dev/urandom of=sym.key bs=1 count=128

tpm2_import -C parent.ctx -i sym.key -q key.pub -r key.priv
```

## Import an RSA key
```
openssl genrsa -out private.pem 2048

tpm2_import -C parent.ctx -G rsa -i private.pem -u key.pub -r key.priv
```

## Import an ECC key
```
openssl ecparam -name prime256v1 -genkey -noout -out private.ecc.pem

tpm2_import -C parent.ctx -G ecc -i private.ecc.pem -u key.pub -r key.priv
```

# LIMITATIONS
  * The TPM requires that the name algorithm of the child be smaller than the parent.
  * Parents with a SHA1 hash algorithm currently fail. See bug
    [#119](https://github.com/tpm2-software/tpm2-tools/issues/1119) for details.

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
