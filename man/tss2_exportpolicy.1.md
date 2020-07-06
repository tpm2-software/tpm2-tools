% tss2_policyexport(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_policyexport**(1) -

# SYNOPSIS

**tss2_policyexport** [*OPTIONS*]

[common fapi references](common/tss2-fapi-references.md)

# DESCRIPTION

**tss2_policyexport**(1) - This commands exports a policy associated with a key
in JSON encoding.

# OPTIONS

These are the available options:

  * **-f**, **\--force**:

    Force overwriting the output file.

  * **-o**, **\--jsonPolicy**=_FILENAME_ or _-_ (for stdout):

    Returns the JSON-encoded policy.

  * **-p**, **\--path**=_STRING_:

    The path of the key.

[common tss2 options](common/tss2-options.md)

# EXAMPLE
```
tss2_exportpolicy --path=HS/SRK/myRSASign --jsonPolicy=jsonPolicy.json
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
