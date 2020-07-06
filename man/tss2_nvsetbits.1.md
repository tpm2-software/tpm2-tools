% tss2_nvsetbits(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_nvsetbits**(1) -

# SYNOPSIS

**tss2_nvsetbits** [*OPTIONS*]

[common fapi references](common/tss2-fapi-references.md)

# DESCRIPTION

**tss2_nvsetbits**(1) - This command sets bits in an NV Index that was created as a bit field. Any number of bits from 0 to 64 may be set. The contents of bitmap are ORed with the current contents of the NV Index.

# OPTIONS

These are the availabe options:

  * **-i**, **\--bitmap**=_BITS_:

    A mask indicating which bits to set in the NV space.

  * **-p**, **\--nvPath**=_STRING_:

    Identifies the NV space to write.

[common tss2 options](common/tss2-options.md)

# EXAMPLE
```
tss2_nvsetbits --nvPath=/nv/Owner/NvBitmap --bitmap=0x0102030405060608
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
