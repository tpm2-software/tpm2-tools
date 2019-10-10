% tss2_nvread(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_nvread**(1) -

# SYNOPSIS

**tss2_nvread** [*OPTIONS*]

# DESCRIPTION

**tss2_nvread**(1) - This command reads the entire data from an NV index of the TPM. The FAPI will automatically perform multiple read operations with the TPM if the NV index is larger than the TPM's TPM2_MAX_NV_BUFFER_SIZE.

# OPTIONS

These are the availabe options:

  * **-f**, **\--force**:

    Force overwriting the output file.

  * **-o**, **\--data**:

    Returns the value read from the NV space. MUST NOT be NULL.

  * **-p**, **\--nvPath**:

    Identifies the NV space to read. MUST NOT be NULL.

  * **-l**, **\--logData**:

    Returns the JSON encoded log, if the NV index is of type “extend” and an empty string otherwise. MAY be NULL.

[common tss2 options](common/tss2-options.md)

# EXAMPLE

tss2_nvread --nvPath /nv/Owner/myNVwrite --data nv_read_data.file


# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
