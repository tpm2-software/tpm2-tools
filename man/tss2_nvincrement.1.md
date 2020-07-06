% tss2_nvincrement(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_nvincrement**(1) -

# SYNOPSIS

**tss2_nvincrement** [*OPTIONS*]

[common fapi references](common/tss2-fapi-references.md)

# DESCRIPTION

**tss2_nvincrement**(1) - This command increments by 1 an NV index that is of type counter.

# OPTIONS

These are the availabe options:

  * **-p**, **\--nvPath**=_STRING_:

    Identifies the NV space to increment.

[common tss2 options](common/tss2-options.md)

# EXAMPLE
```
tss2_nvincrement --nvPath=/nv/Owner/myNVcounter
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
