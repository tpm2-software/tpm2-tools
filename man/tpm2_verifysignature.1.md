% tpm2_verifysignature(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_verifysignature**(1) - Validates a signature using the TPM.

# SYNOPSIS

**tpm2_verifysignature** [*OPTIONS*]

# DESCRIPTION

**tpm2_verifysignature**(1) uses loaded keys to validate a signature on a message
with the message digest passed to the TPM. If the signature check succeeds,
then the TPM will produce a **TPMT_TK_VERIFIED**. Otherwise, the TPM shall return
**TPM_RC_SIGNATURE**. If _KEY\_HANDLE_ references an asymmetric key, only the
public portion of the key needs to be loaded. If _KEY\_HANDLE_ references a
symmetric key, both the public and private portions need to be loaded.

# OPTIONS

  * **-k**, **--key-handle**=_KEY\_HANDLE_:

    Handle of key that will used in the validation.

  * **-c**, **--key-context**=_KEY\_CONTEXT\_FILE_:

    Filename of the key context used for the operation.

  * **-g**, **--halg**=_HASH\_ALGORITHM_:

    The hash algorithm used to digest the message.
    Algorithms should follow the "formatting standards, see section
    "Algorithm Specifiers".
    Also, see section "Supported Hash Algorithms" for a list of supported hash
    algorithms.

  * **-m**, **--message**=_MSG\_FILE_:

    The message file, containing the content to be  digested.

  * **-D**, **--digest**=_DIGEST\_FILE_:

    The input hash file, containing the hash of the message. If this option is
    selected, then the message (**-m**) and algorithm (**-g**) options do not need
    to be specified.

  * **-s**, **--sig**=_SIG\_FILE_:

    The input signature file of the signature to be validated.

  * **-t**, **--ticket**=_TICKET\_FILE_:

    The ticket file to record the validation structure.

  * **-S**, **--input-session-handle**=_SESSION\_HANDLE_:

    Optional Input session handle from a policy session for authorization.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[authorization formatting](common/password.md)

[supported hash algorithms](common/hash.md)

[algorithm specifiers](common/alg.md)

# EXAMPLES

```
tpm2_verifysignature -k 0x81010001 -g sha256 -m <filePath> -s <filePath> -t <filePath>
tpm2_verifysignature -k 0x81010001 -D <filePath> -s <filePath> -t <filePath>
tpm2_verifysignature -c key.context -g sha256 -m <filePath> -s <filePath> -t <filePath>
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
