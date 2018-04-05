% tpm2_rsadecrypt(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_rsadecrypt**(1) - Performs an RSA Decryption operation using the TPM.

# SYNOPSIS

**tpm2_tpm2_rsadecrypt** [*OPTIONS*]

# DESCRIPTION

**tpm2_rsadecrypt**(1) performs RSA decryption using the indicated padding scheme according to
IETF RFC 3447 (PKCS#1). The scheme of keyHandle should not be **TPM_ALG_NULL**.

The key referenced by key-context is **required** to be:

1. an RSA key
2. Have the attribute *decrypt* **SET** in it's attributes.

# OPTIONS

  * **-c**, **--key-context**=_KEY\_CONTEXT\_OBJECT_:

    Context object pointing to the the public portion of RSA key to use for
    decryption. Either a file or a handle number.
    See section "Context Object Format".

  * **-P**, **--auth-key**=_KEY\_AUTH_:

    Optional authorization value to use the key specified by **-k**.
    Authorization values should follow the authorization formatting standards,
    see section "Authorization Formatting".

  * **-I**, **--in-file**=_INPUT\FILE_:

    Input file path, containing the data to be decrypted.

  * **-o**, **--out-file**=_OUTPUT\_FILE_:

    Output file path, record the decrypted data.

  * **-S**, **--session**=_SESSION\_FILE_:

    Optional, A session file from **tpm2_startauthsession**(1)'s **-S** option.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[context object format](commmon/ctxobj.md)

[authorization formatting](common/password.md)

# EXAMPLES

```
tpm2_rsadecrypt -C 0x81010001 -I encrypted.in -o plain.out
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
