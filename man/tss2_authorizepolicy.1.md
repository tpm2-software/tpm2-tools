% tss2_authorizepolicy(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_authorizepolicy**(1) -

# SYNOPSIS

**tss2_authorizepolicy** [*OPTIONS*]

# DESCRIPTION

**tss2_authorizepolicy**(1) - This command signs a given policy with a given key such that the policy can be referenced from other policies that contain a corresponding PolicyAuthorize elements.

# OPTIONS

These are the available options:

  * **-P**, **\--policyPath**:
    Path of the new policy. MUST NOT be NULL.

  * **-p**, **\--keyPath**:
    Path of the signing key. MUST NOT be NULL.

  * **-r**, **\--policyRef**:
    A byte buffer to be included in the signature. MAY be NULL if policyRefSize is 0.

[common tss2 options](common/tss2-options.md)

# EXAMPLE

tss2_authorizepolicy --keyPath HS/SRK/myPolicySignKey --policyPath policy/pcr-policy --policyRef policyRef.file

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
