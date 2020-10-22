% tpm2_zgen2phase(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_zgen2phase**(1) - Command to enable the TPM to combine data from the
other party with the ephemeral key generated in the first phase of two-phase
key exchange protocols.


# SYNOPSIS

**tpm2_zgen2phase** [*OPTIONS*]

# DESCRIPTION

**tpm2_zgen2phase**(1) - Command to enable the TPM to combine data from the
other party with the ephemeral key generated in the first phase of two-phase
key exchange protocols.

# OPTIONS

  * **-c**, **\--key-context**=_FILE_:

    Context object pointing to ECC key.
    Either a file or a handle number. See section "Context Object Format".

  * **-p**, **\--key-auth**=_AUTH_:

    The authorization value for the ECC key object.

  * **-s**, **\--scheme**=_ALGORITHM_:

    The key exchange scheme. Optional. Valid options are ecdh or sm2.

  * **-t**, **\--counter**=_NATURALNUMBER_:

    The commit count to determine the key index to use.

  * **\--static-public**=_FILE_:

    The static public key input of the other party.

  * **\--ephemeral-public**=_FILE_:

    The ephemeral public key input of the other party.

  * **\--output-Z1**=_FILE_

    Specify file path to save the calculated ecdh secret Z1 point.

  * **\--output-Z2**=_FILE_

    Specify file path to save the calculated ecdh secret Z2 point.

## References

[algorithm specifiers](common/alg.md) details the options for specifying
cryptographic algorithms _ALGORITHM_.

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

```bash
tpm2_createprimary -C o -c prim.ctx -Q

tpm2_create -C prim.ctx -c key.ctx -u key.pub -r key.priv -G ecc256:ecdh -Q

tpm2_ecephemeral -u ecc.q -t ecc.ctr ecc256

tpm2_ecdhkeygen -u ecdh.pub -o ecdh.priv -c key.ctx

tpm2_zgen2phase -c key.ctx --static-public ecdh.pub --ephemeral-public ecc.q \
-t 0 --output-Z1 z1.bin --output-Z2 z2.bin
```

[returns](common/returns.md)

[footer](common/footer.md)
