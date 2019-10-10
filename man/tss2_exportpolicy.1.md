% tss2_policyexport(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_policyexport**(1) -

# SYNOPSIS

**tss2_policyexport** [*OPTIONS*]

# DESCRIPTION

**tss2_policyexport**(1) - This commands exports a policy associated with a key
in JSON encoding. The exported policy SHALL be encoded according to TCG TSS 2.0 JSON Policy Language Specification.

# OPTIONS

These are the available options:

  * **-f**, **\--force**:

    Force overwriting the output file.

  * **-o**, **\--jsonPolicy**:

    Returns the JSON-encoded policy. MUST NOT be NULL.

  * **-p**, **\--path**:

    The path of the key. MUST NOT be NULL.

[common tss2 options](common/tss2-options.md)

# EXAMPLE

tss2_exportpolicy --path HS/SRK/myRSASign --jsonPolicy pcr-policy.json

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
