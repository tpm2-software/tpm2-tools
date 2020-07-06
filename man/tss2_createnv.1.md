% tss2_createnv(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_createnv**(1) -

# SYNOPSIS

**tss2_createnv** [*OPTIONS*]

[common fapi references](common/tss2-fapi-references.md)

# DESCRIPTION

**tss2_createnv**(1) - This command creates an NV index in the TPM.

# OPTIONS

These are the available options:

  * **-p**, **\--path**=_STRING_:

    Path of the new NV space.

    The path is composed of three elements, separated by "/". An nvPath starts
    with "/nv". The second path element identifies the NV handle range
    for the nv object. This includes the following values:
    Owner, TPM, Platform, Endorsement_Certificate, Platform_Certificate,
    Component_OEM, TPM_OEM, Platform_OEM, PC-Client, Server,
    Virtualized_Platform, MPWG, Embedded. The third path element identifies
    the actual NV-Index using a meaningful name.

  * **-t**, **\--type**=_STRING_:

    Identifies the intended usage. Optional parameter.
    Types may be any comma-separated combination of:

        - "noda": Sets the noda attribute of a key or NV index.
        - "bitfield": Sets the NV type to bitfield.
        - "counter": Sets the NV type to counter.
        - "pcr": Sets the NV type to pcr-like behavior.
        - Hint: If none of the previous three keywords is provided a regular NV
          index is created.


  * **-s**, **\--size**=_INTEGER_:

    The size in bytes of the NV index to be created. Can be omitted if size can
    be inferred from the type; e.g. an NV index of type counter has a size of 8
    bytes.

  * **-P**, **\--policyPath**=_STRING_:

    Identifies the policy to be associated with the new NV space. Optional parameter.
    If omitted then no policy will be associated with the key.

    A policyPath is composed of two elements, separated by "/". A policyPath
    starts with "/policy". The second path element identifies the policy
    or policy template using a meaningful name.

  * **-a**, **\--authValue**=_STRING_:

    The new UTF-8 password. Optional parameter. If it is neglected then the user
    is queried interactively for a password. To set no password, this option
    should be used with the empty string (""). The maximum password size is
    determined by the digest size of the chosen name hash algorithm in the
    cryptographic profile (cf., **fapi-profile(5)**). For example, choosing
    SHA256 as hash algorithm, allows passwords of a maximum size of 32 characters.

[common tss2 options](common/tss2-options.md)

# EXAMPLE
```
tss2_createnv --authValue=abc --path=/nv/Owner/myNV --size=20 --type="noDa"
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
