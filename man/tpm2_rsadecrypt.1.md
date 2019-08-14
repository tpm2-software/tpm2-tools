% tpm2_rsadecrypt(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_rsadecrypt**(1) - Performs an RSA decryption operation using the TPM.

# SYNOPSIS

**tpm2_rsadecrypt** [*OPTIONS*] _FILE_

# DESCRIPTION

**tpm2_rsadecrypt**(1) - Performs RSA decryption on the contents of _FILE_
using the indicated padding scheme according to IETF RFC 3447 (PKCS#1).
Input defaults to *stdin* if not specified.

The key referenced by key-context is **required** to be:

1. An RSA key
2. Have the attribute *decrypt* **SET** in it's attributes.

# OPTIONS

  * **-c**, **\--key-context**=_KEY\_CONTEXT\_OBJECT_:

    Context object pointing to the the public portion of RSA key to use for
    decryption. Either a file or a handle number.
    See section "Context Object Format".

  * **-p**, **\--auth**=_KEY\_AUTH_:

    Optional authorization value to use the key specified by **-k**.
    Authorization values should follow the "authorization formatting standards",
    see section "Authorization Formatting".

  * **-o**, **\--output**=_OUTPUT\_FILE_:

    Optional output file path to record the decrypted data to. The default is to print
    the binary encrypted data to stdout.

  * **-s**, **\--scheme**=_PADDING\_SCHEME_:

    Optional, set the padding scheme (defaults to rsaes).

    * null  - TPM_ALG_NULL uses the key's scheme if set.
    * rsaes - TPM_ALG_RSAES which is RSAES_PKCSV1.5.
    * oaep  - TPM_ALG_OAEP which is RSAES_OAEP.

  * **-l**, **\--label**=_LABEL\_DATA_:

    Optional, set the label data. Can either be a string or file path. The TPM requires the last
    byte of the label to be zero, this is handled internally to the tool. No other embedded 0
    bytes can exist or the TPM will truncate your label.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[context object format](common/ctxobj.md)

[authorization formatting](common/authorizations.md)

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
