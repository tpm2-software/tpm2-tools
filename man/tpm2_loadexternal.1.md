% tpm2_loadexternal(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_loadexternal**(1) - Load an external object into the TPM. This command
loads an external object into the TPM, forgoing TPM protections. Ie, the key
material is not protected by the parent objects seed.

# SYNOPSIS

**tpm2_loadexternal** [*OPTIONS*]

# DESCRIPTION

**tpm2_loadexternal**(1) - Load an object that is not a Protected Object into the
TPM. The command allows loading of a public area or both a public and a
sensitive area.

# OPTIONS

  * **-a**, **\--hierarchy**=_HIERARCHY_:

    Hierarchy to use for the ticket, optional. Defaults to **n**, **null**.
    Supported options are:
      * **o** for the **owner** hierarchy.
      * **p** for the **platform** hierarchy.
      * **e** for the **endorsement** hierarchy.
      * **n** for the **null** hierarchy.

  * **-G**, **\--key-alg**=_ALGORITHM_:

    The algorithm used by the key to be imported. Supports:
    * **aes** - AES 128,192 or 256 key.
    * **rsa** - RSA 1024 or 2048 key.
    * **ecc** - ECC NIST P192, P224, P256, P384 or P521 public and private key.

  * **-u**, **\--pubfile**=_PUBLIC\_FILE_:

    The public portion of the object, this can be one of the following file formats:
      * TSS - The TSS/TPM format. For example from option `-u` of command **tpm2_create**(1).
      * RSA - OSSL PEM formats. For example `public.pem` from the command
        `openssl rsa -in private.pem -out public.pem -pubout`
      * ECC - OSSL PEM formats. For example `public.pem` from the command
        `openssl ec -in private.ecc.pem -out public.ecc.pem -pubout`

  * **-r**, **\--privfile**=_PRIVATE\_FILE_:

    The sensitive portion of the object, optional. If one wishes to use the private portion
    of a key, this must be specified. Like option **-u**, this command takes files in the
    following format:
      * RSA - OSSL PEM formats. For example `private.pem` from the command
        `openssl genrsa -out private.pem 2048`
        Since an RSA public key can be derived from the private PEM file, their is no
        need to specify -u for the public portion.

    *Note*: The private portion does not respect TSS formats as it's impossible to get a **TPM2B_SENSITIVE** output from a previous command.

  * **-p**, **\--auth-key**=_KEY\_AUTH_:

    The authorization value for the key, optional.
    Follows the authorization formatting of the
    "password for parent key" option: **-P**.

  * **-L**, **\--policy-file**=_POLICY\_FILE_:

    The input policy file, optional. A file containing the hash of a policy derived from
    `tpm2_createpolicy`.

  * **-g**, **\--halg**=_NAME\_ALGORITHM_:

    The hash algorithm for generating the objects name. This is optional
    and defaults to sha256 when not specified. However, load external supports
    having a *null* name algorithm. In this case, no cryptographic binding checks
    between the public and private portions are performed.
    Algorithms should follow the "formatting standards", see section "Algorithm Specifiers".
    Also, see section "Supported Hash Algorithms" for a list of supported
    hash algorithms.

  * **-b**, **\--object-attributes**=_ATTRIBUTES_:

    The object attributes, optional. Object attributes follow the specifications
    as outlined in "object attribute specifiers". The default for created objects is:
    `TPMA_OBJECT_SIGN_ENCRYPT|TPMA_OBJECT_DECRYPT`. Optionally, if -p is specified or no
    `-p` or `-L` is specified then `TPMA_OBJECT_USERWITHAUTH` is added to the default
    attribute set.

    *Note*: If specifying attributes, the TPM will reject certain attributes like
    **TPMA_OBJECT_FIXEDTPM**, as those guarantees cannot be made.

  * **-o**, **\--out-context**=_CONTEXT\_FILE_

    The file name of the saved object context, required.

  * **-n**, **\--name**=_NAME\_DATA\_FILE_:

    An optional file to save the object name, which is in a binary hash format.
    The size of the hash is based on name algorithm or the **-g** option.

  * **\--passin**=_OSSL\_PEM\_FILE\_PASSWORD_

    An optional password for an Open SSL (OSSL) provided input file.
    It mirrors the -passin option of OSSL and is known to support the pass,
    file, env, fd and plain password formats of openssl.
    (see *man(1) openssl*) for more.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[authorization formatting](common/authorizations.md)

[supported hash algorithms](common/hash.md)

[supported public object algorithms](common/object-alg.md)

# OUTPUT
The tool outputs the name of the loaded object in a YAML format and saves a
context file for future interactions with the object. The context file name
defaults to *object.ctx* and can be specified with **-o**.

## Example output via stdout
```
transient-context: object.ctx
name: 0x000b44e59fa5658ab443834a069a488ecc1f6d7deb47c40c6ec49871ef57d7036b43
```

# NOTES

* If the hierarchy is *null* or the name hashing algorithm is *null*, tickets produced using the object
  will be NULL.

* If the private portion of an object is specified, the hierarchy must be *null* or the TPM will reject
  loading it.


# EXAMPLES

## Load a TPM generateed public key into the *owner* hierarchy
```
tpm2_create -G rsa -u pub.dat -r priv.dat

tpm2_loadexternal -a o -u pub.dat
```

## Load an RSA public key into the *owner* hierarchy
```
genrsa -out private.pem 2048

openssl rsa -in private.pem -out public.pem -outform PEM -pubout

tpm2_loadexternal -a n -Grsa -u public.pem
```

## Load an RSA key-pair into the *null* hierarchy
```
genrsa -out private.pem 2048

tpm2_loadexternal -a n -Grsa -r private.pem
```

## Load an AES key into the *null* hierarchy
```
dd if=/dev/urandom of=sym.key bs=1 count=16

tpm2_loadexternal -a n -Gaes -r sym.key
```

[returns](common/returns.md)

[footer](common/footer.md)
