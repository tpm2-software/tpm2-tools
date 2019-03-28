% tpm2_pcrallocate(1) tpm2-tools | General Commands Manual
%
% MARCH 2019

# NAME

**tpm2_pcrallocate**(1) - Change the allocated PCRs of a TPM

# SYNOPSIS

**tpm2_pcrallocate** [*OPTIONS*] [*ALLOCATION*]

# DESCRIPTION

**tpm2_pcrallocate**(1) - allows the user to specify an allocation for the TPM.
If no *ALLOCATION* is given, then SHA1 and SHA256 banks with PCRs 0 - 23 are
allocated.

Note: The new allocations become effective after the next reboot.

# ALLOCATION

A list of banks and selected pcrs. The _ALLOCATION_ values should 
follow the pcr bank specifiers standards, see section "PCR Bank Specifiers".


# OPTIONS

  * **-P**, **--auth-platform**=_AUTH\_HIERARCHY_\VALUE_:

    Optional authorization value. Authorization values should follow the
    "authorization formatting standards", see section "Authorization Formatting".

[common options](common/options.md)

[common tcti options](common/tcti.md)

[context object format](common/ctxobj.md)

[authorization formatting](common/authorizations.md)

[pcr bank specifiers](common/pcr.md)

# EXAMPLES

## To allocate the two default banks
```
tpm2_pcrallocate
```
## To make a custom allocation with a platform authorization
```
tpm2_pcrallocate -P abc sha1:7,8,9,10,16,17,18,19+sha256:all
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
