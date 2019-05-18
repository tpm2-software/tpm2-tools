% tpm2_rsadecrypt(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_rsadecrypt**(1) - Performs an RSA decryption operation using the TPM.

# SYNOPSIS

**tpm2_rsadecrypt** [*OPTIONS*]

# DESCRIPTION

**tpm2_rsadecrypt**(1) - Performs RSA decryption using the indicated padding scheme according to
IETF RFC 3447 (PKCS#1). The scheme of keyHandle should not be **TPM_ALG_NULL**.

The key referenced by key-context is **required** to be:

1. An RSA key
2. Have the attribute *decrypt* **SET** in it's attributes.

# OPTIONS

  * **-c**, **\--key-context**=_KEY\_CONTEXT\_OBJECT_:

    Context object pointing to the the public portion of RSA key to use for
    decryption. Either a file or a handle number.
    See section "Context Object Format".

  * **-p**, **\--auth-key**=_KEY\_AUTH_:

    Optional authorization value to use the key specified by **-k**.
    Authorization values should follow the "authorization formatting standards",
    see section "Authorization Formatting".

  * **-i**, **\--in-file**=_INPUT\FILE_:

    Input file path, containing the data to be decrypted.

  * **-o**, **\--out-file**=_OUTPUT\_FILE_:

    Output file path, record the decrypted data.

  * **-g**, **\--scheme**=_PADDING\_SCHEME_:

    Optional, set the padding scheme (defaults to rsaes).

    * null  - TPM_ALG_NULL
    * rsaes - TPM_ALG_RSAES
    * oaep  - TPM_ALG_OAEP

[common options](common/options.md)

[common tcti options](common/tcti.md)

[context object format](common/ctxobj.md)

[authorization formatting](common/authorizations.md)

# EXAMPLES

```
tpm2_rsadecrypt -C 0x81010001 -i encrypted.in -o plain.out
```

[returns](common/returns.md)

[footer](common/footer.md)
