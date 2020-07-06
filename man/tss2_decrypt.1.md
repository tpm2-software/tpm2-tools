% tss2_decrypt(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_decrypt**(1) - decrypts data

# SYNOPSIS

**tss2_decrypt** [*OPTIONS*]

[common fapi references](common/tss2-fapi-references.md)

# DESCRIPTION

**tss2_decrypt**(1) - This command decrypts data that was encrypted using tss2_encrypt
using the TPM decryption schemes as specified in the cryptographic profile
(cf., **fapi-profile(5)**).


# OPTIONS

These are the available options:

  * **-p**, **\--keyPath**=_STRING_:

    Identifies the decryption key.

  * **-i**, **\--cipherText**=_FILENAME_ or _-_ (for stdin):

    The JSON-encoded cipherText.

  * **-f**, **\--force**:

    Force Overwriting the output file.

  * **-o**, **\--plainText**=_FILENAME_ or _-_ (for stdout):

    Returns the decrypted data. Optional parameter.

[common tss2 options](common/tss2-options.md)

# EXAMPLE
```
    tss2_decrypt --keyPath=HS/SRK/myRSACrypt --cipherText=cipherText.file --plainText=plainText.file
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
