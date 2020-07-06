% tss2_quote(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_quote**(1) -

# SYNOPSIS

**tss2_quote** [*OPTIONS*]

[common fapi references](common/tss2-fapi-references.md)

# DESCRIPTION

**tss2_quote**(1) - This command performs an attestation using the TPM. The PCR bank for each provided PCR index and signing scheme are set in the cryptographic profile
(cf., **fapi-profile(5)**).

# OPTIONS

These are the available options:

  * **-x**, **\--pcrList**=_STRING_:

    An array holding the PCR indices to quote against.

  * **-Q**, **\--qualifyingData**=_FILENAME_ or _-_ (for stdin):

    A nonce provided by the caller to ensure freshness of the signature. Optional parameter.

  * **-l**, **\--pcrLog**=_FILENAME_ or _-_ (for stdout):

    Returns the PCR log for the chosen PCR. Optional parameter.

    PCR event logs are a list (arbitrary length JSON array) of log entries with
    the following content.

        - recnum: Unique record number
        - pcr: PCR index
        - digest: The digests
        - type: The type of event. At the moment the only possible value is: "LINUX_IMA" (legacy IMA)
        - eventDigest: Digest of the event; e.g. the digest of the measured file
        - eventName: Name of the event; e.g. the name of the measured file.

  * **-f**, **\--force**:

    Force overwriting the output file.

  * **-p**, **\--keyPath**=_STRING_:

    Identifies the signing key.

  * **-q**, **\--quoteInfo**=_FILENAME_ or _-_ (for stdout):

    Returns a JSON-encoded structure holding the inputs to the quote operation. This includes the digest value and PCR values.

  * **-o**, **\--signature**=_FILENAME_ or _-_ (for stdout):

    Returns the signature over the quoted material.

  * **-c**, **\--certificate**=_FILENAME_ or _-_ (for stdout):

    The certificate associated with keyPath in PEM format. Optional parameter.

[common tss2 options](common/tss2-options.md)

# EXAMPLE
```
tss2_quote --keyPath=HS/SRK/quotekey --pcrList="10,16" --qualifyingData=qualifyingData.file --signature=signature.file --pcrLog=pcrLog.file --certificate=certificate.file --quoteInfo=quoteInfo.info
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
