% tss2_pcrextend(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_pcrextend**(1) -

# SYNOPSIS

**tss2_pcrextend** [*OPTIONS*]

[common fapi references](common/tss2-fapi-references.md)

# DESCRIPTION

**tss2_pcrextend**(1) - This command extends the data into the PCR listed. The parameter logData is extended into the PCR log. If the logData is NULL, only the PCR extend takes place. All PCRs currently active in the TPM are extended.

# OPTIONS

These are the available options:

  * **-x**, **\--pcr**=_INTEGER_:

   The PCR to extend.

  * **-i**, **\--data**=_FILENAME_ or _-_ (for stdin):

    The event data to be extended.

  * **-l**, **\--logData**=_FILENAME_ or _-_ (for stdin):

    Contains a JSON representation of data to be written to the PCR's event log. Optional parameter.


[common tss2 options](common/tss2-options.md)

# EXAMPLE
```
tss2_pcrextend --pcr=16 --data=data.file --logData=logData.file
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
