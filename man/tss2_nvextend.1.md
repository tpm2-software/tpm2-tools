% tss2_nvextend(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_nvextend**(1) -

# SYNOPSIS

**tss2_nvextend** [*OPTIONS*]

# DESCRIPTION

**tss2_nvextend**(1) - This command performs an extend options on an NV index of type extend (i.e. an NV index that behaves similar to a PCR).

# OPTIONS

These are the available options:

  * **-i**, **\--data**:

    The data to be extended into the NV space. MUST NOT be NULL.

  * **-p**, **\--nvPath**:

    Identifies the NV space to write. MUST NOT be NULL.

  * **-l**, **\--logData**:

    A JSON representation of data to be written to the PCR’s event log. MAY be NULL.

[common tss2 options](common/tss2-options.md)

# EXAMPLE

tss2_nvextend --nvPath /nv/Owner/NvExtend --data nv_write_data.file --logData log.data

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
