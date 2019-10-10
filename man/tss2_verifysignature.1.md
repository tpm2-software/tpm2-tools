% tss2_verifysignature(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_verifysignature**(1) -

# SYNOPSIS

**tss2_verifysignature** [*OPTIONS*]

# DESCRIPTION

**tss2_verifysignature**(1) - This command verifies a signature using a public key found in a keyPath. This function MAY or MAY NOT use the TPM for this operation.

# OPTIONS

These are the available options:

  * **-d**, **\--digest**:

    The data that was signed, already hashed. MUST NOT be NULL

  * **-p**, **\--keyPath**:

    Path to the verification public key. MUST NOT be NULL.

  * **-i**, **\--signature**:

    The signature to be verified. MUST NOT be NULL.


[common tss2 options](common/tss2-options.md)

# EXAMPLE

tss2_verifysignature --keyPath ext/myRSASign --digest digest.file --signature signature.file

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
