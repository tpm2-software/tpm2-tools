% tpm2_quote(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_quote**(1) - Provide a quote and signature from the TPM.

# SYNOPSIS

**tpm2_quote** [*OPTIONS*]

# DESCRIPTION

**tpm2_quote**(1) - Provide quote and signature for given list of PCRs in given algorithm/banks.

# OPTIONS

  * **-C**, **\--ak-context**=_AK\_CONTEXT\_OBJECT_:

    Context object for the existing AK's context. Either a file or a handle number.
    See section "Context Object Format".

  * **-P**, **\--ak-auth**=_AK\_AUTH_:

    Specifies the authorization value for AK specified by option **-C**.
    Authorization values should follow the "authorization formatting standards",
    see section "Authorization Formatting".

  * **-i**, **\--pcr-index**=_PCR\_ID\_LIST_

    The comma separated list of selected PCRs' e.g. "4,5,6".

  * **-l**, **\--pcr-list**=_PCR\_SELECTION\_LIST_:

    The list of PCR banks and selected PCRs' ids for each bank.
    _PCR\_SELECTION\_LIST_ values should follow the
    PCR bank specifiers standards, see section "PCR Bank Specifiers".

    Also see **NOTES** section below.

  * **-m**, **\--message**:

    Message output file, records the quote message that makes up the data that
    is signed by the TPM.

  * **-s**, **\--signature**:

    Signature output file, records the signature in the format specified via the **-f**
    option.

  * **-F**, **\--format**

    Format selection for the signature output file. See section "Signature Format Specifiers".

  * **-f**, **\--pcr**:

    PCR output file, optional, records the list of PCR values as defined
    by **-l** or **-L**.  Note that only the digest of these values is stored in the
    signed quote message \-- these values themselves are not signed or
    stored in the message.

  * **-q**, **\--qualification-data**:

    Data given as a Hex string to qualify the  quote, optional. This is typically
    used to add a nonce against replay attacks.

  * **-g**, **\--hash-algorithm**:

    Hash algorithm for signature. Required if **-p** is given.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[context object format](common/ctxobj.md)

[authorization formatting](common/authorizations.md)

[pcr bank specifiers](common/pcr.md)

[signature format specifiers](common/signature.md)

# EXAMPLES

```
tpm2_quote -C 0x81010002 -P abc123 -i 16,17,18

tpm2_quote -C ak.context -P "str:abc123" -i 16,17,18

tpm2_quote -C 0x81010002 -l sha1:16,17,18

tpm2_quote -C ak.dat -l sha1:16,17,18

tpm2_quote -C 0x81010002 -P "hex:123abc" -l sha1:16,17,18+sha256:16,17,18 -q 11aa22bb
```

# NOTES

The maximum number of PCR that can be quoted at once is associated
with the maximum length of a bank.

On most TPMs, it means that this tool can quote up to 24 PCRs
at once.

[returns](common/returns.md)

[footer](common/footer.md)
