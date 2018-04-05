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

  * **-c**, **--key-context**=_KEY\_CONTEXT\_OBJECT_:

    Context object pointing to the the key used for signing. Either a file or a
    handle number. See section "Context Object Format".

  * **-P**, **--auth-key**=_KEY\_AUTH_:

    Optional authorization value to use the key specified by **-k**.
    Authorization values should follow the authorization formatting standards,
    see section "Authorization Formatting".

  * **-g**, **--halg**=_HASH\_ALGORITHM_:

    The hash algorithm used to digest the message.
    Algorithms should follow the "formatting standards, see section
    "Algorithm Specifiers".
    Also, see section "Supported Hash Algorithms" for a list of supported hash
    algorithms.


  * **-m**, **--message**=_MSG\_FILE_:

    The message file, containing the content to be  digested.

  * **-D**, **--digest**=_DIGEST\_FILE_:

    The digest file that shall be computed using the correct hash
    algorithm. When this option is specified, a warning is generated and
    **both the message file (-m) and the validation ticket (-t) are
    ignored**.
    You cannot use this option to sign a digest against a restricted
    signing key.

  * **-t**, **--ticket**=_TICKET\_FILE_:

    The ticket file, containing the validation structure, optional.

  * **-s**, **--sig**=_TICKET\_FILE_:

    The signature file, records the signature structure.

  * **-f**, **--format**

    Format selection for the signature output file. See section "Signature Format Specifiers".

[common options](common/options.md)

[common tcti options](common/tcti.md)

[context object format](commmon/ctxobj.md)

[authorization formatting](common/password.md)

[supported hash algorithms](common/hash.md)

[algorithm specifiers](common/alg.md)

[signature format specifiers](common/signature.md)

# EXAMPLES


```
tpm2_sign -C 0x81010001 -P abc123 -g sha256 -m <filePath> -s <filePath> -t <filePath>
tpm2_sign -C file:key.context -P abc123 -g sha256 -m <filePath> -s <filePath> -t <filePath>
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
