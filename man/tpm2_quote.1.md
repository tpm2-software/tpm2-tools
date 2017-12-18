% tpm2_quote(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_quote**(1) - Provide a quote and signature from the TPM.

# SYNOPSIS

**tpm2_quote** [*OPTIONS*]

# DESCRIPTION

**tpm2_quote**(1) Provide quote and signature for given list of PCRs in given algorithm/banks.

# OPTIONS

  * **-k**, **--ak-handle**=_AK\_HANDLE_:

    Handle of existing AK.

  * **-c**, **--ak-context**=_AK\_CONTEXT\_FILE_:

    Filename for the existing AK's context.

  * **-P**, **--ak-passwd**=_AK\_PASSWORD_:

    specifies the password of _AK\_HANDLE_. Passwords should follow the
    password formatting standards, see section "Password Formatting".

  * **-l**, **--id-list**=_PCR\_ID\_LIST_

	The comma separated list of selected PCRs' ids, 0~23 e.g. "4,5,6".

  * **-L**, **--sel-list**=_PCR\_SELECTION\_LIST_:

    The list of pcr banks and selected PCRs' ids for each bank.
    _PCR\_SELECTION\_LIST_ values should follow the
    pcr bank specifiers standards, see section "PCR Bank Specfiers".

  * **-m**, **--message**:

    message output file, records the quote message that makes up the data that
    is signed by the TPM.

  * **-s**, **--signature**:

    signature output file, records the signature in the format specified via the **-f**
    option.

  * **-f**, **--format**

    Format selection for the signature output file. See section "Signature Format Specifiers".

  * **-q**, **--qualify-data**:

    Data given as a Hex string to qualify the  quote, optional. This is typically
    used to add a nonce against replay attacks.

  * **-S**, **--input-session-handle**=_SESSION\_HANDLE_:
    Optional Input session handle from a policy session for authorization.

  * **-G**, **--sig-hash-algorithm**:

    Hash algorithm for signature.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[password formatting](common/password.md)

[pcr bank specifiers](common/password.md)

[signature format specifiers](common/signature.md)

# EXAMPLES

```
tpm2_quote -k 0x81010002 -P abc123 -g sha1 -l 16,17,18
tpm2_quote -c ak.context -P "str:abc123" -g sha1 -l 16,17,18
tpm2_quote -k 0x81010002 -g sha1 -l 16,17,18
tpm2_quote -c ak.context -g sha1 -l 16,17,18
tpm2_quote -k 0x81010002 -P "hex:123abc" -L sha1:16,17,18+sha256:16,17,18 -q 11aa22bb
```

# RETURNS

0 on success or 1 on failure.

# BUGS

[Github Issues](https://github.com/01org/tpm2-tools/issues)

# HELP

See the [Mailing List](https://lists.01.org/mailman/listinfo/tpm2)
