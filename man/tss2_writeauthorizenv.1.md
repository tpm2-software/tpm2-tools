% tss2_writeauthorizenv(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_writeauthorizenv**(1) -

# SYNOPSIS

**tss2_writeauthorizenv** [*OPTIONS*]

# DESCRIPTION

**tss2_writeauthorizenv**(1) - This command writes the digest value of a policy to an NV index such that this policy can be used in other policies containing a corresponding PolicyAuthorizeNv element. Note that the nameAlg property of the NV index defines the digest algorithm for the policy.

# OPTIONS

These are the available options:

  * **-p**, **\--nvPath**:

    The path of the NV index. MUST NOT be NULL.

  * **-P**, **\--policyPath**:

    The path of the new policy. MUST NOT be NULL.

[common tss2 options](common/tss2-options.md)

# EXAMPLE

tss2_writeauthorizenv --nvPath /nv/Owner/myNV --policyPath pcr-policy

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
