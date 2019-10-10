% tss2_createnv(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_createnv**(1) -

# SYNOPSIS

**tss2_createnv** [*OPTIONS*]

# DESCRIPTION

**tss2_createnv**(1) - This command creates an NV index in the TPM. The path is constructed as described in section 1.7.2. The type field is described in section 1.8.

# OPTIONS

These are the available options:

  * **-p**, **\--path**:

    Path of the new NV space. MUST NOT be NULL.

  * **-t**, **\--type**:

    Identifies the intended usage. For possible values see FAPI specification. MAY be NULL.

  * **-s**, **\--size**:

    The size in bytes of the NV index to be created. MAY be zero if the size is inferred from the type; e.g. an NV index of type counter has a size of 8 bytes.

  * **-P**, **\--policyPath**:

    Identifies the policy to be associated with the new NV space. MAY be NULL. If NULL then no policy will be associated with the NV space.

  * **-a**, **\--authValue**:

    The new authorization value for the nv index. MAY be NULL. If NULL then the authorization value will be the empty string


[common tss2 options](common/tss2-options.md)

# EXAMPLE

tss2_createnv --authValue abc --path /nv/Owner/myNV --size 20 --type "noDa"

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
