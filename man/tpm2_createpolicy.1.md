% tpm2_createpolicy(1) tpm2-tools | General Commands Manual
%
% AUGUST 2017

# NAME

**tpm2_createpolicy**(1) - Creates simple assertion authorization policies based on
multiple PCR indices values across multiple enabled banks.

# SYNOPSIS

**tpm2_createpolicy** [*OPTIONS*]

# DESCRIPTION

**tpm2_createpolicy**(1) - Creates simple assertion authorization policies based on
multiple PCR indices values across multiple enabled banks. It can then be used with
object creation and or tools using the object.

# OPTIONS

These options control creating the policy authorization session:

  * **-o**, **--out-policy-file**=_POLICY\_FILE_:

    File to save the policy digest.

  * **--policy-pcr**:

    Identifies the PCR policy type for policy creation.

  * **-g**, **--policy-digest-alg**=_HASH\_ALGORITHM_:

    The hash algorithm used in computation of the policy digest. Algorithms
    should follow the "formatting standards", see section "Algorithm Specifiers".
    Also, see section "Supported Hash Algorithms" for a list of supported hash
    algorithms.

  * **-L**, **--set-list**=_PCR\_LIST_:

    The list of PCR banks and selected PCRs' ids for each bank.

  * **-F**, **--pcr-input-file**=_PCR\_FILE_:

    Optional Path or Name of the file containing expected PCR values for the
    specified index. Default is to read the current PCRs per the set list.

  * **--policy-session**:

    Start a policy session of type **TPM_SE_POLICY**. Default without this option
    is **TPM_SE_TRIAL**.
    **NOTE**: A *trial* session is used when building a policy and a *policy*
    session is used when authenticating with a policy.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[supported hash algorithms](common/hash.md)

[algorithm specifiers](common/alg.md)

# EXAMPLES

## Create a authorization policy tied to a specific PCR index
```
tpm2_createpolicy --policy-pcr -L 0x4:0 -o policy.file -F pcr0.bin
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
