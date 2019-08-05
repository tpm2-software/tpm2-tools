% tpm2_rsaencrypt(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_rsaencrypt**(1) - Performs an RSA encryption operation using the TPM.

# SYNOPSIS

**tpm2_rsaencrypt** [*OPTIONS*] _FILE_

# DESCRIPTION

**tpm2_rsaencrypt**(1) - Performs RSA encryption on the contents of _FILE_
using the indicated padding scheme according to IETF RFC 3447 (PKCS#1).
Input defaults to *stdin* if not specified.

The key referenced by key-context is **required** to be:

1. An RSA key
2. Have the attribute *encrypt* **SET** in it's attributes.

# OPTIONS

  * **-c**, **\--key-context**=_KEY\_CONTEXT\_OBJECT_:

    Context object pointing to the the public portion of RSA key to use for
    encryption. Either a file or a handle number.
    See section "Context Object Format".

  * **-o**, **\--output**=_OUTPUT\_FILE_:

    Optional output file path to record the decrypted data to. The default is to print
    the binary encrypted data to stdout.

  * **-g**, **\--scheme**=_PADDING\_SCHEME_:

    Optional, set the padding scheme (defaults to rsaes).

    * null  - TPM_ALG_NULL uses the key's scheme if set.
    * rsaes - TPM_ALG_RSAES which is RSAES_PKCSV1.5.
    * oaep  - TPM_ALG_OAEP which is RSAES_OAEP.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[context object format](common/ctxobj.md)

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
tpm2_rsadecrypt -c key.ctx -o msg.ptext -i msg.enc
cat msg.ptext
my message
```

[returns](common/returns.md)

[footer](common/footer.md)
