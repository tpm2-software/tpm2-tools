% tss2_gettpmblobs(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_gettpmblobs**(1) -

# SYNOPSIS

**tss2_gettpmblobs** [*OPTIONS*]

# DESCRIPTION

**tss2_gettpmblobs**(1) - This command returns the public and private blobs of an object, such that they could be loaded by a low-level API (e.g. ESAPI). It also returns the policy associated with these blobs in JSON format.

# OPTIONS

These are the available options:

  * **-f**, **\--force**:

    Force overwriting the output file.

  * **-p**, **\--path**:

    The path of the object for which the blobs will be returned. MUST NOT be NULL.

  * **-u**, **\--tpm2bPublic**:

    The returned public area of the object as a marshalled TPM2B_PUBLIC. MAY be NULL.

  * **-r**, **\--tpm2bPrivate**:

    The returned private area of the object as a marshalled TPM2B_PRIVATE. MAY be NULL.

  * **-l**, **\--policy**:

    The returned policy associated with the object, encoded in JSON. policy MAY be NULL.

[common tss2 options](common/tss2-options.md)

# EXAMPLE

tss2_gettpmblobs --path HS/SRK/myRSACrypt --tpm2bPublic public.file --tpm2bPrivate private.file --policy policy.file

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
