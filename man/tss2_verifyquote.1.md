% tss2_verifyquote(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_verifyquote**(1) -

# SYNOPSIS

**tss2_verifyquote** [*OPTIONS*]

[common fapi references](common/tss2-fapi-references.md)

# DESCRIPTION

**tss2_verifyquote**(1) - This command verifies that the data returned by a quote is valid. This includes

  * Reconstructing the quoteInfo's PCR values from the eventLog (if an eventLog was provided)
  * Verifying the quoteInfo using the signature and the publicKeyPath

The used signature verification scheme is specified in the cryptographic profile (cf., **fapi-profile(5)**).

An application using tss2_verifyquote() will further have to

  * Assess the publicKey's trustworthiness
  * Assess the eventLog entries' trustworthiness

# OPTIONS

These are the available options:

  * **-Q**, **\--qualifyingData**=_FILENAME_ or _-_ (for stdin):

    A nonce provided by the caller to ensure freshness of the signature. Optional parameter.

  * **-l**, **\--pcrLog**=_FILENAME_ or _-_ (for stdin):

    Returns the PCR event log for the chosen PCR. Optional parameter.

    PCR event logs are a list (arbitrary length JSON array) of log entries with
    the following content.

        - recnum: Unique record number
        - pcr: PCR index
        - digest: The digests
        - type: The type of event. At the moment the only possible value is: "LINUX_IMA" (legacy IMA)
        - eventDigest: Digest of the event; e.g. the digest of the measured file
        - eventName: Name of the event; e.g. the name of the measured file.

  * **-q**, **\--quoteInfo**=_FILENAME_ or _-_ (for stdin):

    The JSON-encoded structure holding the inputs to the quote operation. This includes the digest value and PCR values.

  * **-k**, **\--publicKeyPath**=_STRING_:

    Identifies the signing key. MAY be a path to the public key hierarchy /ext.

  * **-i**, **\--signature**=_FILENAME_ or _-_ (for stdin):

    The signature over the quoted material.

[common tss2 options](common/tss2-options.md)

# EXAMPLE

```
    tss2_verifyquote --publicKeyPath="ext/myNewParent" --qualifyingData=qualifyingData.file --quoteInfo=quoteInfo.file --signature=signature.file --pcrLog=pcrLog.file
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
