% tss2_encrypt(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_encrypt**(1) - encrypts data

# SYNOPSIS

**tss2_encrypt** [*OPTIONS*]

[common fapi references](common/tss2-fapi-references.md)

# DESCRIPTION

**tss2_encrypt**(1) - This command encrypts the provided data for a target key
using the TPM encryption schemes as specified in the cryptographic profile
(cf., **fapi-profile(5)**).

# OPTIONS

These are the available options:

  * **-p**, **\--keyPath**=_STRING_:

    Identifies the encryption key.

  * **-f**, **\--force**:

    Force overwriting the output file.

  * **-i**, **\--plainText**=_FILENAME_ or _-_ (for stdin):

    The data to be encrypted.

  * **-o**, **\--cipherText**=_FILENAME_ or _-_ (for stdout):

    Returns the JSON-encoded ciphertext.

[common tss2 options](common/tss2-options.md)

# EXAMPLE
```
  tss2_encrypt --keyPath=HS/SRK/myRSACrypt --plainText=plainText.file --cipherText=cipherText.file
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
