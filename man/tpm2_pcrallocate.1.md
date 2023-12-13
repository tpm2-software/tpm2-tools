% tpm2_pcrallocate(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_pcrallocate**(1) - Configure PCRs and bank algorithms.

# SYNOPSIS

**tpm2_pcrallocate** [*OPTIONS*] [*ARGUMENT]

# DESCRIPTION

**tpm2_pcrallocate**(1) - Allow the user to specify a PCR allocation for the TPM.
An allocation is the enabling or disabling of PCRs and it's banks. A PCR can have
multiple banks, where each bank is associated with a specific hashing algorithm.
Allocation is specified in the argument.

If no allocation is given, then SHA1 and SHA256 banks with PCRs 0 - 23 are
allocated.

Allocation is a list of banks and selected pcrs. The values should follow the
pcr bank specifiers standards, see section "PCR Bank Specifiers".

The new allocations become effective after the next reboot.

**Note**: This command requires platform authorization.

# OPTIONS

  * **-P**, **\--auth**=_AUTH_:

    Optional authorization value. Authorization values should follow the
    "authorization formatting standards", see section "Authorization Formatting".

  * **ARGUMENT** the command line argument specifies the PCR allocation.

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash.

## References

[context object format](common/ctxobj.md) details the methods for specifying
_OBJECT_.

[authorization formatting](common/authorizations.md) details the methods for
specifying _AUTH_.

[algorithm specifiers](common/alg.md) details the options for specifying
cryptographic algorithms _ALGORITHM_.

[object attribute specifiers](common/obj-attrs.md) details the options for
specifying the object attributes _ATTRIBUTES_.

[pcr bank specifiers](common/pcr.md) details the syntax for specifying pcr list.

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

## To allocate the two default banks (SHA1 and SHA256)
```bash
tpm2_pcrallocate
```

## To make a custom allocation with a platform authorization
```bash
tpm2_pcrallocate -P abc sha1:7,8,9,10,16,17,18,19+sha256:all
```

## To completly switch from SHA1 bank to SHA256 with a platform authorization
```bash
tpm2_pcrallocate -P abc sha1:none+sha256:all
```

[returns](common/returns.md)

[footer](common/footer.md)
