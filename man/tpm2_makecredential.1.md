% tpm2_makecredential(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_makecredential**(1) - load an object that is not a Protected Object into the
TPM.

# SYNOPSIS

**tpm2_makecredential** [*OPTIONS*]

# DESCRIPTION

**tpm2_makecredential**(1) - Use a TPM public key to protect a secret that is used
to encrypt the AK certififcate.

# OPTIONS

  * **-e**, **--enckey**=_PUBLIC\_FILE_:
    A tpm Public Key which was used to wrap the seed.

  * **-s**, **--sec**=_SECRET\_DATA\_FILE_:
    The secret which will be protected by the key derived from the random seed.

  * **-n**, **--name**=_NAME_
    The name of the key for which certificate is to be created.

  * **-o**, **--out-file**=_OUT\_FILE_
    The output file path, recording the two structures output by
    tpm2_makecredential function.

[common options](common/options.md)

[common tcti options](common/tcti.md)

# EXAMPLES

```
tpm2_makecredential -e <keyFile> -s <secFile> -n <hexString> -o <outFile>
```

# RETURNS

0 on success or 1 on failure.

# BUGS

[Github Issues](https://github.com/01org/tpm2-tools/issues)

# HELP

See the [Mailing List](https://lists.01.org/mailman/listinfo/tpm2)