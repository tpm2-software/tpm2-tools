% tpm2_testparms(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_testparms**(1) - Verify that specified algorithm suite is supported by TPM

# SYNOPSIS

**tpm2_testparms** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_testparms**(1) - Checks that the suite specified by _ALG\_SPEC_ is
available for usage per _ALGORITHM_.

Algorithms should follow the "formatting standards", see section "Algorithm Specifiers".

Also, see section "Supported Signing Schemes" for a list of supported hash algorithms.

# OPTIONS

This tool accepts no tool specific options.

## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

[algorithm specifiers](common/alg.md) details the options for specifying
cryptographic algorithms _ALGORITHM_.

[signature format specifiers](common/signature.md)

# EXAMPLES

## Check whether if "rsa" is supported
```bash
tpm2_testparms rsa
```

## Check that ECDSA using P-256 with AES-128 CTR mode is available
```bash
tpm2_testparms ecc256:ecdsa:aes128ctr
```

[returns](common/returns.md)

[footer](common/footer.md)
