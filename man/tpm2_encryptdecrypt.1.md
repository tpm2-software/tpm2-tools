% tpm2_encryptdecrypt(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_encryptdecrypt**(1) - Performs symmetric encryption or decryption.

# SYNOPSIS

**tpm2_encryptdecrypt** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_encryptdecrypt**(1) - Performs symmetric encryption or decryption with a
specified symmetric key on the contents of _FILE_.
If _FILE_ is not specified, defaults to *stdin*.

# OPTIONS

  * **-c**, **\--key-context**=_OBJECT_:

    The encryption key object.

  * **-p**, **\--auth**=_AUTH_:

    The authorization value for the encryption key object.

  * **-d**, **\--decrypt**:

    Perform a decrypt operation. Defaults to encryption when this option is not
    specified.

  * **-e**, **\--pad**:

    Enable pkcs7 padding for applicable AES encryption modes cfb/cbc/ecb.
    Applicable only to encryption and for input data with last block shorter
    than encryption block length.

  * **-o**, **\--output**=_FILE_ or _STDOUT_:

    The output file path for either the encrypted or decrypted data. If not
    specified, defaults to **stdout**.

  * **-G**, **\--mode**=_ALGORITHM_:

    The key algorithm associated with this object. Defaults to object properties
    or CFB if not defined.

  * **-t**, **\--iv**=_FILE_:

    Optional initialization vector to use. Defaults to 0's. Syntax allows for an
    input file and output file source to be specified. The input file path is
    first, optionally followed by a colon ":" and the output iv path. This
    output iv can be saved for subsequent calls when chaining.

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash.

  * **ARGUMENT** the command line argument specifies the input file path _FILE_
    of the data to encrypt or decrypt.

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

# Create an AES key
```bash
tpm2_createprimary -c primary.ctx
tpm2_create -C primary.ctx -Gaes128 -u key.pub -r key.priv
tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
```

# Encrypt and Decrypt some data
```bash
echo "my secret" > secret.dat
tpm2_encryptdecrypt -c key.ctx -o secret.enc secret.dat
tpm2_encryptdecrypt -d -c key.ctx -o secret.dec secret.enc
cat secret.dec
my secret
```

[returns](common/returns.md)

[footer](common/footer.md)
