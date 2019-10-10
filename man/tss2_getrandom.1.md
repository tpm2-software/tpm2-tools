% tss2_getrandom(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_getrandom**(1) -
# SYNOPSIS

**tss2_getrandom** [*OPTIONS*]

# DESCRIPTION

**tss2_getrandom**(1) - This command uses the TPM to create an array of random bytes. This function may perform multiple calls to the TPM if the number of bytes requested by the caller is larger than the maximum number of bytes that the TPM will return per call.


# OPTIONS

These are the available options:

  * **-n**, **\--numBytes**: \<number\>

    The number of bytes requested by the caller

  * **-f**, **\--force**:

    Force overwriting the output file.

  * **-o**, **\--data**: \<filename\>

    The returned random bytes. MUST NOT be NULL.

[common tss2 options](common/tss2-options.md)

# EXAMPLE

    tss2_getrandom --numBytes 20 -data - | hexdump -C

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
