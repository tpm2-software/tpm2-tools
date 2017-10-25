% tpm2_sign(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_sign**(1) - Sign a hash using the TPM.

# SYNOPSIS

**tpm2_sign** [*OPTIONS*]

# DESCRIPTION

**tpm2_sign**(1) signs an externally provided hash with the specified symmetric or
asymmetric signing key. If keyHandle references a restricted signing key, then
validation shall be provided, indicating that the TPM performed the hash of the
data and validation shall indicate that hashed data did not start with
**TPM_GENERATED_VALUE**. The scheme of keyHandle should not be **TPM_ALG_NULL**.

# OPTIONS

  * **-k**, **--key-handle**=_KEY\_HANDLE_:

    Handle of key that will perform signing.

  * **-c**, **--key-context**=_KEY\_CONTEXT\_FILE_:

    Filename of the key context used for the operation.

  * **-P**, **--pwdk**=_KEY\_PASSWORD_:

    Specifies the password of _KEY\_HANDLE_. Passwords should follow the
    password formatting standards, see section "Password Formatting".

  * **-g**, **--halg**=_HASH\_ALGORITHM_:

    The hash algorithm used to digest the message.
    Algorithms should follow the "formatting standards, see section
    "Algorithm Specifiers".
    Also, see section "Supported Hash Algorithms" for a list of supported hash
    algorithms.


  * **-m**, **--msg**=_MSG\_FILE_:

    The message file, containing the content to be  digested.

  * **-t**, **--ticket**=_TICKET\_FILE_:

    The ticket file, containning the validation structure, optional.

  * **-s**, **--sig**=_TICKET\_FILE_:

    The signature file, records the signature structure.

  * **-f**, **--format**

    Format selection for the signature output file. See section "Signature Format Specifiers".

  * **-S**, **--input-session-handle**=_SESSION\_HANDLE_:

    Optional Input session handle from a policy session for authorization.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[password formatting](common/password.md)

[supported hash algorithms](common/hash.md)

[algorithm specifiers](common/alg.md)

[signature format specifiers](common/signature.md)

# EXAMPLES


```
tpm2_sign -k 0x81010001 -P abc123 -g sha256 -m <filePath> -s <filePath> -t <filePath>
tpm2_sign -c key.context -P abc123 -g sha256 -m <filePath> -s <filePath> -t <filePath>
```

# RETURNS

0 on success or 1 on failure.

# BUGS

[Github Issues](https://github.com/01org/tpm2-tools/issues)

# HELP

See the [Mailing List](https://lists.01.org/mailman/listinfo/tpm2)
