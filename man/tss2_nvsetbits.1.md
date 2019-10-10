% tss2_nvsetbits(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_nvsetbits**(1) -

# SYNOPSIS

**tss2_nvsetbits** [*OPTIONS*]

# DESCRIPTION

**tss2_nvsetbits**(1) - This command sets bits in an NV Index that was created as a bit field. Any number of bits from 0 to 64 may be SET. The contents of bitmap are ORed with the current contents of the NV Index.

# OPTIONS

These are the availabe options:

  * **-i**, **\--bitmap**:

    A mask indicating which bits to set in the NV space.

  * **-p**, **\--nvPath**:

    Identifies the NV space to write. MUST NOT be NULL.

[common tss2 options](common/tss2-options.md)

# EXAMPLE

tss2_nvsetbits --nvPath /nv/Owner/NvBitmap --bitmap 0x0102030405060608

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
