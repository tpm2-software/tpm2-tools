% tss2_writeauthorizenv(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_writeauthorizenv**(1) -

# SYNOPSIS

**tss2_writeauthorizenv** [*OPTIONS*]

# DESCRIPTION

**tss2_writeauthorizenv**(1) - This command writes the digest value of a policy to an NV index such that this policy can be used in other policies containing a corresponding PolicyAuthorizeNv element.

# OPTIONS

These are the available options:

  * **-p**, **\--nvPath**=_STRING_:

    The path of the NV index.

  * **-P**, **\--policyPath**=_STRING_:

    The path of the new policy.

[common tss2 options](common/tss2-options.md)

# EXAMPLE

```
tss2_writeauthorizenv --nvPath=/nv/Owner/myNV --policyPath=/policy/pcr-policy
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
