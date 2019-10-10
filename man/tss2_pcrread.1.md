% tss2_pcrread(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_pcrread**(1) -

# SYNOPSIS

**tss2_pcrread** [*OPTIONS*]

# DESCRIPTION

**tss2_pcrread**(1) - This command provides a PCRs value and corresponding Event log. The PCR bank to be used per PCR is defined in the cryptographic profile.

# OPTIONS

These are the available options:

  * **-o**, **\--pcrValue**:

    Returns PCR digest. MAY be NULL.

  * **-x**, **\--pcrIndex**:

    Identifies the PCR to read.

  * **-f**, **\--force**:

    Force overwriting the output files.

  * **-l**, **\--pcrLog**:

    Returns the PCR log for that PCR in the format defined in the FAPI specification. MAY be NULL.

[common tss2 options](common/tss2-options.md)

# EXAMPLE

tss2_pcrread --pcrIndex 16 --pcrValue pcr_digest.file --pcrLog pcr_log_read.file

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
