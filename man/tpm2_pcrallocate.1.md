% tpm2_pcrallocate(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_pcrallocate**(1) - Configure PCRs and bank algorithms.

# SYNOPSIS

**tpm2_pcrallocate** [*OPTIONS*] _ALLOCATION_

# DESCRIPTION

**tpm2_pcrallocate**(1) - Allow the user to specify a PCR allocation for the TPM.
An allocation is the enabling or disabling of PCRs and it's banks. A PCR can have
multiple banks, where each bank is associated with a specific hashing algorithm.

If no _ALLOCATION_ is given, then SHA1 and SHA256 banks with PCRs 0 - 23 are
allocated.

_ALLOCATION_ is a list of banks and selected pcrs. The values should
follow the pcr bank specifiers standards, see section "PCR Bank Specifiers".

The new allocations become effective after the next reboot.

**Note**: This command requires platform authorization.

# OPTIONS

  * **-P**, **\--auth**=_PLATFORM\_AUTH\_VALUE_:

    Optional authorization value. Authorization values should follow the
    "authorization formatting standards", see section "Authorization Formatting".

[common options](common/options.md)

[common tcti options](common/tcti.md)

[context object format](common/ctxobj.md)

[authorization formatting](common/authorizations.md)

[pcr bank specifiers](common/pcr.md)

# EXAMPLES

## To allocate the two default banks (SHA1 and SHA256)
```
tpm2_pcrallocate
```

## To make a custom allocation with a platform authorization
```
tpm2_pcrallocate -P abc sha1:7,8,9,10,16,17,18,19+sha256:all
```

[returns](common/returns.md)

[footer](common/footer.md)
