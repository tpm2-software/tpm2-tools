% tss2_decrypt(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_decrypt**(1) - decrypts data

# SYNOPSIS

**tss2_decrypt** [*OPTIONS*]

# DESCRIPTION

**tss2_decrypt**(1) - This command decrypts data that was encrypted using tss2_encrypt.


# OPTIONS

These are the available options:

  * **-p**, **\--keyPath**:

    Identifies the decryption key.

  * **-i**, **\--cipherText**: \<filename\>

    The JSON-encoded cipherText.

  * **-f**, **\--force**:

    Force Overwriting the output file.

  * **-o**, **\--plainText**: \<filename\>

    Returns the decrypted data. Optional parameter.

[common tss2 options](common/tss2-options.md)

# EXAMPLE
```
    tss2_decrypt --keyPath HS/SRK/myRSACrypt --cipherText encrypted.file --plainText abc
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
