% tss2_quote(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_quote**(1) -

# SYNOPSIS

**tss2_quote** [*OPTIONS*]

# DESCRIPTION

**tss2_quote**(1) - This command performs an attestation using the TPM. The PCR bank for each provided PCR index is set in the cryptographic profile.

# OPTIONS

These are the available options:

  * **-x**, **\--pcrList**:

    An array holding the PCR indices to quote against. MUST NOT be NULL.

  * **-Q**, **\--qualifyingData**:

    A nonce provided by the caller to ensure freshness of the signature. MAY be
    NULL.

  * **-l**, **\--pcrLog**:

    Returns the PCR log for the chosen PCR in the format defined in the FAPI specification. MAY be NULL.

  * **-f**, **\--force**:

    Force overwriting the output file.

  * **-p**, **\--keyPath**:

    Identifies the signing key. MUST NOT be NULL.

  * **-q**, **\--quoteInfo**:

    Returns a JSON-encoded structure holding the inputs to the quote operation. This includes the digest value and PCR values. MUST NOT be NULL.

  * **-o**, **\--signature**:

    Returns the signature over the quoted material. MUST NOT be NULL.

  * **-c**, **\--certificate**:

    The certificate associated with keyPath in PEM format. MAY be NULL.

[common tss2 options](common/tss2-options.md)

# EXAMPLE

tss2_quote --keyPath HS/SRK/quotekey --pcrList "16" --qualifyingData nonce.file --signature signature.file --pcrLog pcr.log --certificate certificate.file --quoteInfo quote.info

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
