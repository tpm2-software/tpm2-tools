% tpm2_testparms(1) tpm2-tools | General Commands Manual
%
% MARCH 2019

# NAME

**tpm2_testparms**(1) - Verify that specified algorithm suite is supported by TPM

# SYNOPSIS

**tpm2_testparms** [*OPTIONS*] _ALG\_SPEC_

# DESCRIPTION

**tpm2_testparms**(1) checks that the suite specified by _ALG\_SPEC_ is available for
usage.

Algorithms should follow the "formatting standards", see section "Algorithm Specifiers".

Also, see section "Supported Signing Schemes" for a list of supported hash algorithms.

# OPTIONS

This tool accepts no tool specific options.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[algorithm specifiers](common/alg.md)

[supported hash algorithms](common/hash.md)

[supported signing schemes](common/signschemes.md)

# EXAMPLES

Check whether if "rsa" is supported:

```
tpm2_testparms rsa
```

Check that ECDSA signing scheme using P-256 curve with AES 128 CTR mode is available :

```
tpm2_testparms ecc256:ecdsa:aes128ctr
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
