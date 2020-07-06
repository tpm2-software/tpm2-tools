% tss2_authorizepolicy(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_authorizepolicy**(1) -

# SYNOPSIS

**tss2_authorizepolicy** [*OPTIONS*]

[common fapi references](common/tss2-fapi-references.md)

# DESCRIPTION

**tss2_authorizepolicy**(1) - This command signs a given policy with a given key such that the policy can be referenced from other policies that contain a corresponding PolicyAuthorize elements. The signature is done using the TPM signing schemes as specified in the cryptographic profile (cf., **fapi-profile(5)**).

# OPTIONS

These are the available options:

  * **-P**, **\--policyPath**=_STRING_:
    Path of the new policy.

    A policyPath is composed of two elements, separated by "/". A policyPath
    starts with "/policy". The second path element identifies the policy
    or policy template using a meaningful name.

  * **-p**, **\--keyPath**=_STRING_:
    Path of the signing key.

  * **-r**, **\--policyRef**=_FILENAME_ or _-_ (for stdin):
    A byte buffer to be included in the signature. Optional parameter.

[common tss2 options](common/tss2-options.md)

# EXAMPLE
```
tss2_authorizepolicy --keyPath=HS/SRK/myPolicySignKey --policyPath=/policy/pcr-policy --policyRef=policyRef.file
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
