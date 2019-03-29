% tpm2_getrandom(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_getrandom**(1) - Retrieves random bytes from the TPM.

# SYNOPSIS

**tpm2_getrandom** [*OPTIONS*] _SIZE_

# DESCRIPTION

**tpm2_getrandom**(1) - Returns the next _SIZE_ octets from the random number
generator. The _SIZE_ parameter is expected as the only argument to the tool.

Note that the TPM specification recommends that TPM's fix the number of 
available entry to the maximum size of a hash algorithm output in bytes. 

Most TPMs do this, and thus the tool verifies that input size is bounded by property 
**TPM2_PT_MAX_DIGEST** and issues an error if it is too large.

# OPTIONS

  * **-o**, **--out-file**=_FILE_

    Specifies the filename to output the raw bytes to. Defaults to stdout as a hex
    string.

  * **-f**, **--force**

    Override checking that the:
    - Requested size is within the hash size limit of the TPM.
    - Number of retrieved random bytes matches requested amount.

[common options](common/options.md)

[common tcti options](common/tcti.md)

# EXAMPLES

## Generate a random 20 bytes and output the binary data to a file
```
tpm2_getrandom -o random.out 20
```

## Generate a random 8 bytes and output the hex formatted data to stdout
```
tpm2_getrandom 8
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
