% tpm2_encryptdecrypt(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_encryptdecrypt**(1) - Performs symmetric encryption or decryption.

# SYNOPSIS

**tpm2_encryptdecrypt** [*OPTIONS*] _FILE_

# DESCRIPTION

**tpm2_encryptdecrypt**(1) - Performs symmetric encryption or decryption with a
specified symmetric key on the contents of _FILE_.
If _FILE_ is not specified, defaults to *stdin*.

# OPTIONS

  * **-c**, **\--key-context**=_KEY\_CONTEXT\_OBJECT_:

    Name of the key context object to be used for the  operation. Either a file
    or a handle number. See section "Context Object Format".

  * **-p**, **\--auth**=_KEY\_AUTH_:

    Optional authorization value to use the key specified by **-c**.
    Authorization values should follow the "authorization formatting standards",
    see section "Authorization Formatting".

  * **-d**, **\--decrypt**:

    Perform a decrypt operation. Default is encryption.

  * **-e**, **\--pad**:

    Enable pkcs7 padding for applicable AES encryption modes cfb/cbc/ecb.
    Applicable only to encryption and for input data with last block shorter
    than encryption block length.

  * **-o**, **\--output**=_OUT\_FILE_:

    Optional. Specifies the output file path for either the encrypted or decrypted
    data, depending on option **-D**. If not specified, defaults to **stdout**.

  * **-G**, **\--mode**=_CIPHER\_MODE\_ALGORITHM_:

    The key algorithm associated with this object. It defaults to the object's
    mode or CFB if left unconfigured.

    It accepts friendly names just like **-g** option.
    See section "Supported Public Object Algorithms" for a list
    of supported object algorithms.

  * **-t**, **\--iv**=_IV\_INPUT\_FILE_ : _IV\_OUTPUT\_FILE_:

    Optional. The initialization vector to use. Defaults to 0's. The specification
  syntax allows for an input file and output file source to be specified. The input file
  path is first, optionally followed by a colon ":" and the output iv path. This the output
  iv can be saved for subsequent calls when chaining.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[context object format](common/ctxobj.md)

[authorization formatting](common/authorizations.md)

[supported public object algorithms](common/object-alg.md)

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
