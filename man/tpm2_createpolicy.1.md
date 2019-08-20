% tpm2_createpolicy(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_createpolicy**(1) - Creates simple assertion authorization policies based
on multiple PCR indices values across multiple enabled banks.

# SYNOPSIS

**tpm2_createpolicy** [*OPTIONS*]

# DESCRIPTION

**tpm2_createpolicy**(1) - Creates simple assertion authorization policies based
on multiple PCR indices values across multiple enabled banks. It can then be
used with object creation and or tools using the object.

# OPTIONS

These options control creating the policy authorization session:

  * **-L**, **\--policy**=_FILE_:

    The file to save the policy digest.

  * **\--policy-pcr**:

    Identifies the PCR policy type for policy creation.

  * **-g**, **\--policy-algorithm**=_ALGORITHM_:

    The hash algorithm used in computation of the policy digest.

  * **-l**, **\--pcr-list**=_PCR_:

    The list of PCR banks and selected PCRs' ids for each bank.

  * **-f**, **\--pcr**=_FILE_:

    Optional Path or Name of the file containing expected PCR values for the
    specified index. Default is to read the current PCRs per the set list.

  * **\--policy-session**:

    Start a policy session of type **TPM_SE_POLICY**.
    Defaults to **TPM_SE_TRIAL** if this option isn't specified.

## References

[algorithm specifiers](common/alg.md) details the options for specifying
cryptographic algorithms _ALGORITHM_.

[common options](common/pcr.md) details options for specifying the pcr index and
bank/algorithm _PCR_.

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.


# EXAMPLES

## Create a authorization policy tied to a specific PCR index
```bash
tpm2_createpolicy \--policy-pcr -l 0x4:0 -L policy.file -f pcr0.bin
```

[returns](common/returns.md)

[footer](common/footer.md)
