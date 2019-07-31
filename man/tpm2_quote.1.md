% tpm2_quote(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_quote**(1) - Provide a quote and signature from the TPM.

# SYNOPSIS

**tpm2_quote** [*OPTIONS*]

# DESCRIPTION

**tpm2_quote**(1) - Provide quote and signature for given list of PCRs in given algorithm/banks.

# OPTIONS

  * **-c**, **\--key-context**=_AK\_CONTEXT\_OBJECT_:

    Context object for the quote signing key. Either a file or a handle number.
    See section "Context Object Format".

  * **-p**, **\--auth**=_AK\_AUTH_:

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

  * **-o**, **\--pcr**:

    PCR output file, optional, records the list of PCR values as defined
    by **-l**.

  * **-q**, **\--qualification**:

    Data given as a Hex string to qualify the  quote, optional. This is typically
    used to add a nonce against replay attacks.

  * **-g**, **\--hash-algorithm**:

    Hash algorithm for signature. Defaults to sha256.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[context object format](common/ctxobj.md)

[authorization formatting](common/authorizations.md)

[pcr bank specifiers](common/pcr.md)

[signature format specifiers](common/signature.md)

# EXAMPLES

```bash
tpm2_createprimary -C e -c primary.ctx

tpm2_create -C primary.ctx -u key.pub -r key.priv

tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx

tpm2_quote -Q -c key.ctx -l 0x0004:16,17,18+0x000b:16,17,18
```

# NOTES

The maximum number of PCR that can be quoted at once is associated
with the maximum length of a bank.

On most TPMs, it means that this tool can quote up to 24 PCRs
at once.

That this performs a detached signature.

[returns](common/returns.md)

[footer](common/footer.md)
