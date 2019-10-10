% tss2_verifyquote(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_verifyquote**(1) -

# SYNOPSIS

**tss2_verifyquote** [*OPTIONS*]

# DESCRIPTION

**tss2_verifyquote**(1) - This command verifies that the data returned by a quote is valid. This includes

  * Reconstructing the quoteInfo’s PCR values from the eventLog (if an eventLog was provided)
  * Verifying the quoteInfo using the signature and the publicKeyPath

An application using Fapi_VerifyQuote() will further have to

* Assess the publicKey’s trustworthiness
* Assess the eventLog entries’ trustworthiness

# OPTIONS

These are the available options:

  * **-Q**, **\--qualifyingData**:

    A nonce provided by the caller to ensure freshness of the signature. MAY be NULL.

  * **-l**, **\--pcrLog**:

    Returns the PCR log for the chosen PCR in the format defined in the FAPI specification. MAY be NULL.

  * **-q**, **\--quoteInfo**:

    The JSON-encoded structure holding the inputs to the quote operation. This includes the digest value and PCR values. MUST NOT be NULL.

  * **-k**, **\--publicKeyPath**:

    Identifies the signing key. MUST NOT be NULL. MAY be a path to the public key hierarchy /ext.

  * **-i**, **\--signature**:

    The signature over the quoted material. MUST NOT be NULL.

[common tss2 options](common/tss2-options.md)

# EXAMPLE

    tss2_verifyquote --publicKeyPath "ext/myNewParent" --qualifyingData nonce.file --quoteInfo quote.info --signature signature.file --pcrLog pcr.log

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
