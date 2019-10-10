% tss2_pcrextend(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_pcrextend**(1) -

# SYNOPSIS

**tss2_pcrextend** [*OPTIONS*]

# DESCRIPTION

**tss2_pcrextend**(1) - This command extends the data into the PCR listed. The parameter logData is extended into the PCR log. If the logData is NULL, only the PCR extend takes place. All PCRs currently active in the TPM are extended, see
TPM2_PCR_Event.

# OPTIONS

These are the available options:

  * **-x**, **\--pcr**:

   The PCR to extend.

  * **-i**, **\--data**:

    The event data. Note that this data will be hashed using the respective PCR’s hash algorithm. See the TPM2_PCR_Event function of the TPM specification. MUST NOT be NULL.

  * **-l**, **\--logData**:

    Contains a JSON representation of data to be written to the PCR’s event log. MAY be NULL.


[common tss2 options](common/tss2-options.md)

# EXAMPLE

tss2_pcrextend --pcr 16 --data pcr_event_data.file --logData pcr_log_write.file

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
