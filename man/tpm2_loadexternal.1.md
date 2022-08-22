% tpm2_loadexternal(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_loadexternal**(1) - Load an external object into the TPM.

# SYNOPSIS

**tpm2_loadexternal** [*OPTIONS*]

# DESCRIPTION

**tpm2_loadexternal**(1) - This command loads an external object into the TPM,
forgoing TPM protections. Ie, the key material is not protected by the parent
object's seed. It can also be used to load TSS2 Private Keys in pem format.
The command allows loading of just the public portion of an object or both the
public and private portions of an object. For TSS2 Private Keys, only the public
portion of the key is loaded.

The tool outputs the name of the loaded object in a YAML dictionary format
with the key *name* where the value for that key is the name of the object
in hex format, for example:
```yaml
name: 000bac25cb8743111c8e1f52f2ee7279d05d3902a18dd1af694db5d1afa7adf1c8b3
```

It also saves a context file for future interactions with the object.

# OPTIONS

  * **-C**, **\--hierarchy**=_OBJECT_:

    Hierarchy to use for the ticket, optional. Defaults to **n**, **null**.
    Supported options are:
      * **o** for the **owner** hierarchy.
      * **p** for the **platform** hierarchy.
      * **e** for the **endorsement** hierarchy.
      * **n** for the **null** hierarchy.

  * **-G**, **\--key-algorithm**=_ALGORITHM_:

    The algorithm used by the key to be imported. Supports:
    * **aes** - AES 128,192 or 256 key.
    * **rsa** - RSA 1024 or 2048 key.
    * **ecc** - ECC NIST P192, P224, P256, P384 or P521 public and private key.

  * **-u**, **\--public**=_FILE_:

    The public portion of the object, this can be one of the following file
    formats:
      * TSS - The TSS/TPM format. For example from option `-u` of command
        **tpm2_create**(1).
      * RSA - OSSL PEM formats. For example `public.pem` from the command
        `openssl rsa -in private.pem -out public.pem -pubout`
      * ECC - OSSL PEM formats. For example `public.pem` from the command
        `openssl ec -in private.ecc.pem -out public.ecc.pem -pubout`

  * **-r**, **\--private**=_FILE_:

    The sensitive portion of the object, optional. If one wishes to use the
    private portion of a key, this must be specified. Like option **-u**, this
    command takes files in the following format:
      * RSA - OSSL PEM formats. For example `private.pem` from the command
        `openssl genrsa -out private.pem 2048`
        Since an RSA public key can be derived from the private PEM file, their
        is no need to specify -u for the public portion.
      * TSS2 PrivateKey PEM formats.

    *Note*: The private portion does not respect TSS formats as it's impossible
    to get a **TPM2B_SENSITIVE** output from a previous command. They are always
    protected by the TPM as **TPM2B_PRIVATE** blobs.

  * **-p**, **\--auth**=_AUTH_:

    The authorization value for the key, optional.

  * **-L**, **\--policy**=_FILE_ or _HEX\_STRING_:

    The input policy file or hex string, optional. A file or hex string
    containing the hash of a policy derived from `tpm2_createpolicy` or
    another policy digest generating source.

  * **-g**, **\--hash-algorithm**=_ALGORITHM_:

    The hash algorithm for generating the objects name. This is optional
    and defaults to sha256 when not specified. However, load external supports
    having a *null* name algorithm. In this case, no cryptographic binding
    checks between the public and private portions are performed.

  * **-a**, **\--attributes**=_ATTRIBUTES_:

    The object attributes, optional. The default for created objects is:
    `TPMA_OBJECT_SIGN_ENCRYPT|TPMA_OBJECT_DECRYPT`. Optionally, if -p is
    specified or no `-p` or `-L` is specified then `TPMA_OBJECT_USERWITHAUTH`
    is added to the default attribute set.

    *Note*: If specifying attributes, the TPM will reject certain attributes
    like **TPMA_OBJECT_FIXEDTPM**, as those guarantees cannot be made.

  * **-c**, **\--key-context**=_FILE_

    The file name to save the object context, required.

  * **-n**, **\--name**=_FILE_:

    An optional file to save the object name, which is in a binary hash format.
    The size of the hash is based on name algorithm or the **-g** option.

  * **\--passin**=_OSSL\_PEM\_FILE\_PASSWORD_

    An optional password for an Open SSL (OSSL) provided input file.
    It mirrors the -passin option of OSSL and is known to support the pass,
    file, env, fd and plain password formats of openssl.
    (see *man(1) openssl*) for more.

## References

[context object format](common/ctxobj.md) details the methods for specifying
_OBJECT_.

[authorization formatting](common/authorizations.md) details the methods for
specifying _AUTH_.

[algorithm specifiers](common/alg.md) details the options for specifying
cryptographic algorithms _ALGORITHM_.

[object attribute specifiers](common/obj-attrs.md) details the options for
specifying the object attributes _ATTRIBUTES_.

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.


# NOTES

* If the hierarchy is *null* or the name hashing algorithm is *null*, tickets
  produced using the object will be NULL.

* If the private portion of an object is specified, the hierarchy must be *null*
  or the TPM will reject loading it.


# EXAMPLES

## Load a TPM generated public key into the *owner* hierarchy

```bash
tpm2_createprimary -c primary.ctx

tpm2_create -C primary.ctx -u pub.dat -r priv.dat

tpm2_loadexternal -C o -u pub.dat -c pub.ctx
name: 000b9be4d7c6193a57e1bfc86a42a6b03856a91d2f9e77c6cbdb796a783d52d4b3b9
```

## Load an RSA public key into the *owner* hierarchy

```bash
openssl genrsa -out private.pem 2048

openssl rsa -in private.pem -out public.pem -outform PEM -pubout

tpm2_loadexternal -C o -Grsa -u public.pem -c key.ctx
name: 000b7b91d304d16995d42792b57d0fb25df7abe5fdd8afe9950730e00dc5b934ddbc
```

## Load an RSA key-pair into the *null* hierarchy

```bash
openssl genrsa -out private.pem 2048

tpm2_loadexternal -C n -Grsa -r private.pem -c key.ctx
name: 000b635ea220b6c62ec1d02343859dd203c8ac5dad82ebc5b124e407d2502f88691f
```

## Load an AES key into the *null* hierarchy

```bash
dd if=/dev/urandom of=sym.key bs=1 count=16

tpm2_loadexternal -C n -Gaes -r sym.key -c key.ctx
name: 000bfc4d8dd7e4f921bcc9dca4b04f49564243cd9def129a3740002bfd4b9e966d34
```

## Load TSS2 Private Key into the *null* hierarchy

```bash
tpm2_loadexternal -r tss_privkey.pem -c tss_privkey.ctx
name: 000bc5a216702aca9ba226af1214c50dc4dc33ce6269677aa581ea6d9eec7f27000d
```

[returns](common/returns.md)

[footer](common/footer.md)
