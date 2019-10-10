% tss2_import(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_import**(1) -

# SYNOPSIS

**tss2_import** [*OPTIONS*]

# DESCRIPTION

**tss2_import**(1) - This command imports a JSON encoded policy or policy template encoded according to TCG TSS 2.0 JSON Policy Language Specification and stores it under the provided path or it imports a JSON encoded key under the provided path.

# OPTIONS

These are the available options:

  * **-p**, **\--path**:

    The path of the new object. MUST NOT be NULL.

  * **-i**, **\--importData**:

    The data to be imported. MUST NOT be NULL.

[common tss2 options](common/tss2-options.md)

# EXAMPLE

tss2_import --path duplicate_policy --importData pol_duplicate.json

tss2_import --path importedPubKey --importData public_key.file


# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
