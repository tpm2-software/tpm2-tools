% tpm2_pcrreset(1) tpm2-tools | General Commands Manual
%
% JANUARY 2019

# NAME

**tpm2_pcrreset**(1) - Reset one or more PCR banks

# SYNOPSIS

**tpm2_pcrreset** [*OPTIONS*]

# DESCRIPTION

**tpm2_pcrreset**(1) Reset PCR value in all banks for specified index. More than one PCR index can be specified.

The reset value is manufacturer-dependent and is either sequence of 00 or FF on the length of the hash algorithm for each supported bank

# OPTIONS

This tool accepts no tool specific options.

[common options](common/options.md)

[common tcti options](common/tcti.md)

# EXAMPLES

Reset a single PCR:

```
tpm2_pcrreset 23
```

Reset multiple PCRs:

```
tpm2_pcrreset 16 23
```

# NOTES

On operating system's locality (generally locality 0), only PCR-23 can be reset. PCR-16 can also be reset on this locality, depending on TPM manufacturers which could define this PCR as resettable.

PCR 0 to 15 are not resettable (being part of SRTM). PCR 16 to 22 are mostly reserved for DRTM or dedicated to specific localities and might not be resettable depending on current TPM locality.

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
