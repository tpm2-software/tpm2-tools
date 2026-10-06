% tpm2_rewrap(1) tpm2-tools | General Commands Manual

# NAME

tpm2_rewrap(1) -  Rewraps a duplicate object so that it may be imported
with a different parent key.

# SYNOPSIS

**tpm2_rewrap** [*OPTIONS*]

# DESCRIPTION

**tpm2_rewrap**(1) - This tool rewraps a duplicate object so that it can
be imported with a new parent key.

**tpm2_rewrap**(1) removes the outer wrapping of the duplicate object
using the old parent key and wrapping it using the new parent key.
The inner wrapping isn't decrypted and is preserved through the operation,
allowing **tpm2_rewrap**(1) to be used as part of a key backup escrow
or a duplication authority.

# OPTIONS

These options control the key rewrap process:

  * **-c**, **\--parent-context**=_OBJECT_:

    The old parent key object. Can be the null hierarchy.

  * **-p**, **\--parent-auth**=_AUTH_:

    The authorization value for using the old parent key specified with **-c**.

  * **-k**, **\--in-duplicate**=_FILE_:

    Specifies the file path of the private portion of the duplicate object.

  * **-s**, **\--in-seed**=_FILE_:

    Specifies the file path of the encrypted seed for the duplicate object.
    Must be provided unless **-c** is the null hierarchy.

  * **-C**, **\--new-parent-context**=_OBJECT_:

    The new parent key object. Can be the null hierarchy.

  * **-u**, **\--public**=_FILE_:

    Specifies the public key data of the duplicated key.

  * **-K**, **\--out-duplicate**=_FILE_:

    Specifies the file path to save the private portion of the rewrapped object.

  * **-S**, **\--out-seed**=_FILE_:

    Specifies the file path to save the encrypted seed for the rewrapped object.
    Must be provided unless **-C** is the null hierarchy.

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash.

## References

[context object format](common/ctxobj.md) details the methods for specifying
_OBJECT_.

[authorization formatting](common/authorizations.md) details the methods for
specifying _AUTH_.

[algorithm specifiers](common/alg.md) details the options for specifying
cryptographic algorithms _ALGORITHM_.

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

## Rewrap a duplicate object

### TPM-A
Load target key and duplication authority (DA) key
```bash
tpm2_load -c key.ctx -u key.pub ...
tpm2_loadexternal -c da.ctx -u da.pub
```

Perform the duplication to the DA
```bash
tpm2_duplicate -c key.ctx -C da.ctx -r key-da.dpriv -s key-da.seed ...
```
Send `key.pub`, `key-da.dpriv` and `key-da.seed` to the DA.

### Duplication Authority
Load DA key and `TPM-B`'s public key
```bash
tpm2_load -c da.ctx -u da.pub ...
tpm2_loadexternal -c tpm-b.ctx -u tpm-b.pub
```

Perform the rewrap
```bash
tpm2_rewrap -u key.pub -c da.ctx -k key-da.dpriv -s key-da.seed \
        -C tpm-b.ctx -K key-b.dpriv -S key-b.seed
```
Send `key.pub`, `key-b.dpriv` and `key-b.seed` to `TPM-B`.

### TPM-B
Load `TPM-B`'s key
```bash
tpm2_load -c tpm-b.ctx -u tpm-b.pub -r tpm-b.priv
```

Import the target key
```bash
tpm2_import -C tpm-b.ctx -u key.pub -r key.priv -i key-b.dpriv -s key-b.seed
tpm2_load -c key.ctx -C tpm-b.ctx -u key.pub -r key.priv
```

[returns](common/returns.md)

[footer](common/footer.md)
