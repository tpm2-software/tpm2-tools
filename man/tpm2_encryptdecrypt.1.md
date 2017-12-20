% tpm2_encryptdecrypt(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_encryptdecrypt**(1) - performs symmetric encryption or decryption.

# SYNOPSIS

**tpm2_encryptdecrypt** [*OPTIONS*]

# DESCRIPTION

tpm2_encryptdecrypt(1) - performs symmetric encryption or decryption with a
specified symmetric key.

# OPTIONS

  * **-k**, **--key-handle**=_KEY\_HANDLE_:
    the symmetric key used for the operation (encryption/decryption).

  * **-c**, **--key-context**=_KEY\_CONTEXT\_FILE_:
    filename of the key context used for the  operation.

  * **-P**, **--pwdk**=_KEY\_PASSWORD_:
    filename of the key context used for the  operation.
    The password for parent key, optional. Passwords should follow the
    "password formatting standards, see section "Password Formatting".

  * **-D**, **--decrypt**:
    Perform a decrypt operation. Default is encryption.

  * **-I**, **--in-file**=_INPUT\_FILE_:
    Input file path containing data for decrypt or encrypt operation.

  * **-o**, **--out-file**=_OUTPUT\_FILE_:
    Output file path containing data for decrypt or encrypt operation.

  * **-S**, **--input-session-handle**=_SESSION\_HANDLE_:
    Optional Input session handle from a policy session for authorization.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[password formatting](common/password.md)

# EXAMPLES

```
tpm2_encryptdecrypt -k 0x81010001 -P abc123 -D NO -I <filePath> -o <filePath>
tpm2_encryptdecrypt -c key.context -P abc123 -D NO -I <filePath> -o <filePath>
tpm2_encryptdecrypt -k 0x81010001 -P 123abca -D NO -I <filePath> -o <filePath>
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
