% tss2_nvwrite(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_nvwrite**(1) -

# SYNOPSIS

**tss2_nvwrite** [*OPTIONS*]

# DESCRIPTION

**tss2_nvwrite**(1) - This command writes data to a “regular” (not pin, extend or counter) NV index. Only the full index can be written, partial writes are not allowed. If the provided data is smaller than the NV index’s size, then it is padded up with zero bytes at the end. The FAPI will automatically perform multiple write operations with the TPM if the input buffer is larger than the TPM's TPM2_MAX_NV_BUFFER_SIZE.

# OPTIONS

These are the available options:

  * **-i**, **\--data**:

    The data to write to the NV space. MUST NOT be NULL.

  * **-p**, **\--nvPath**:

    Identifies the NV space to write to. MUST NOT be NULL.

[common tss2 options](common/tss2-options.md)

# EXAMPLE

tss2_nvwrite --nvPath /nv/Owner/myNV --data data.file

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
