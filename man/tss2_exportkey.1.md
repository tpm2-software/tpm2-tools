% tss2_exportkey(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_exportkey**(1) -

# SYNOPSIS

**tss2_exportkey** [*OPTIONS*]

# DESCRIPTION

**tss2_exportkey**(1) - This command will duplicate a key and encrypt it using the public key of a new parent. The exported data will contain the re-wrapped key pointed to by the pathOfKeyToDuplicate and then the JSON encoded policy. The exported data SHALL be encoded as described in the FAPI specification.

# OPTIONS

These are the available options:

  * **-e** **\--pathToPublicKeyOfNewParent**:

    The path to the public key of the new parent. This key MAY be in the public key hierarchy /ext. If NULL only the public key will exported.

  * **-f**, **\--force**:

    Force overwriting the output file.

  * **-o**, **\--exportedData**:

    Returns the exported subtree. MUST NOT be NULL.

  * **-p**, **\--pathOfKeyToDuplicate**:

    The path to the root of the subtree to export. MUST NOT be NULL.

[common tss2 options](common/tss2-options.md)

# EXAMPLE

tss2_exportkey --pathOfKeyToDuplicate HS/SRK/myRSADecrypt --exportedData exportedPublicKey

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
