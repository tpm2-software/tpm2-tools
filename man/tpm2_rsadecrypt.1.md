% tpm2_rsadecrypt(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_rsadecrypt**(1) - Performs an RSA decryption operation using the TPM.

# SYNOPSIS

**tpm2_rsadecrypt** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_rsadecrypt**(1) - Performs RSA decryption on the contents of file
using the indicated padding scheme according to IETF RFC 3447 (PKCS#1).
Command line argument defaults to *stdin* if not specified.

The key referenced by key-context is **required** to be:

1. An RSA key
2. Have the attribute *decrypt* **SET** in it's attributes.

# OPTIONS

  * **-c**, **\--key-context**=_OBJECT_:

    Context object pointing to the the public portion of RSA key to use for
    decryption. Either a file or a handle number.
    See section "Context Object Format".

  * **-p**, **\--auth**=_AUTH_:

    Optional authorization value to use the key specified by **-c**.

  * **-o**, **\--output**=_FILE_:

    Optional output file path to record the decrypted data to. The default is to
    print the binary encrypted data to _STDOUT_.

  * **-s**, **\--scheme**=_FORMAT_:

    Optional, set the padding scheme (defaults to rsaes).

    * null  - TPM_ALG_NULL uses the key's scheme if set.
    * rsaes - TPM_ALG_RSAES which is RSAES_PKCSV1.5.
    * oaep  - TPM_ALG_OAEP which is RSAES_OAEP.

  * **-l**, **\--label**=_FILE_ OR _STRING_:

    Optional, set the label data.The TPM requires the last byte of the label to
    be zero, this is handled internally to the tool. No other embedded 0 bytes
    can exist or the TPM will truncate your label.

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash.

  * **ARGUMENT** the command line argument specifies the file containing data to
    be decrypted.

## References

[context object format](common/ctxobj.md) details the methods for specifying
_OBJECT_.

[authorization formatting](common/authorizations.md) details the methods for
specifying _AUTH_.

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.


# EXAMPLES

## Create an RSA key and load it
```bash
tpm2_createprimary -c primary.ctx
tpm2_create -C primary.ctx -Grsa2048 -u key.pub -r key.priv
tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
```

## Encrypt using RSA
```bash
echo "my message" > msg.dat
tpm2_rsaencrypt -c key.ctx -o msg.enc msg.dat
```

## Decrypt using RSA
```bash
tpm2_rsadecrypt -c key.ctx -o msg.ptext msg.enc
cat msg.ptext
my message
```

[returns](common/returns.md)

[footer](common/footer.md)
