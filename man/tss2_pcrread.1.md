% tss2_pcrread(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_pcrread**(1) -

# SYNOPSIS

**tss2_pcrread** [*OPTIONS*]

[common fapi references](common/tss2-fapi-references.md)

# DESCRIPTION

**tss2_pcrread**(1) - This command provides a PCRs value and corresponding event
log. The PCR bank to be used per PCR is defined in the cryptographic profile
(cf., **fapi-profile(5)**).

# OPTIONS

These are the available options:

  * **-o**, **\--pcrValue**=_FILENAME_ or _-_ (for stdout):

    Returns PCR digest. Optional parameter.

  * **-x**, **\--pcrIndex**=_INTEGER_:

    Identifies the PCR to read.

  * **-f**, **\--force**:

    Force overwriting the output files.

  * **-l**, **\--pcrLog**=_FILENAME_ or _-_ (for stdout):

    Returns the PCR log for that PCR. Optional parameter.

    PCR event logs are a list (arbitrary length JSON array) of log entries with
    the following content.

        - recnum: Unique record number
        - pcr: PCR index
        - digest: The digests
        - type: The type of event. At the moment the only possible value is: "LINUX_IMA" (legacy IMA)
        - eventDigest: Digest of the event; e.g. the digest of the measured file
        - eventName: Name of the event; e.g. the name of the measured file.

[common tss2 options](common/tss2-options.md)

# EXAMPLE
```
tss2_pcrread --pcrIndex=16 --pcrValue=pcrValue.file --pcrLog=pcrLog.file
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
