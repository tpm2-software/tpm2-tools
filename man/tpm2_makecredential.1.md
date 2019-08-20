% tpm2_makecredential(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_makecredential**(1) - Load an object that is not a Protected Object into
the TPM.

# SYNOPSIS

**tpm2_makecredential** [*OPTIONS*]

# DESCRIPTION

**tpm2_makecredential**(1) - Use a TPM public key to protect a secret that is
used to encrypt the attestation key certificate. This can be used without a TPM
by using the **none** TCTI option.

# OPTIONS

  * **-e**, **\--encryption-key**=_FILE_:

    A TPM public key which was used to wrap the seed.

  * **-s**, **\--secret**=_FILE_:

    The secret which will be protected by the key derived from the random seed.

  * **-n**, **\--name**=_FILE_:

    The name of the key for which certificate is to be created.

  * **-o**, **\--credential-blob**=_FILE_:

    The output file path, recording the two structures output by
    tpm2_makecredential function.

[common options](common/options.md)

[common tcti options](common/tcti.md)

# EXAMPLES

```bash
tpm2_makecredential -e <keyFile> -s <secFile> -n <hexString> -o <outFile>
```

[returns](common/returns.md)

[footer](common/footer.md)
