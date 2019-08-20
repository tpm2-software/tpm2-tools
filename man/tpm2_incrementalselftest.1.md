% tpm2_incrementalselftest(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_incrementalselftest**(1) - Request testing of specified algorithm list

# SYNOPSIS

**tpm2_incrementalselftest** [*OPTIONS*] _ALG\_SPEC\_LIST_

# DESCRIPTION

**tpm2_incrementalselftest**(1) Request the TPM to perform testing on specified
algorithm and print a list of algorithm scheduled to be tested *OR* remain to be
tested but not scheduled.

The main interest of this command is to reduce delays that might occur on
cryptographic operations as TPM must test the algorithm prior using it.

# ALG\_SPEC\_LIST

A space-separated list of algorithm suite to be tested. Algorithms should follow
the "formatting standards", see section "Algorithm Specifiers". Also, see
section "Supported Hash Algorithms" for a list of supported hash algorithms.

If _ALG\_SPEC\_LIST_ is left empty, **tpm2_incrementalselftest**(1) will return
the list of algorithms left to be tested. Please note that in this case these
algorithms are **NOT** scheduled to be tested.

If _ALG\_SPEC\_LIST_ is not empty, **tpm2_incrementalselftest**(1) will return
the list of algorithms that remains to be tested. This list contains algorithms
scheduled for testing AND algorithms that remains to be tested and not yet
scheduled. This can occur for instance if all AES mode have not been already
tested yet.

# Output
List of algorithms to be tested (implying scheduled) or remain to be tested
(not scheduled) is also printed in YAML format.

If none of the specified algorithm is printed, that means both that they are
already tested AND that these algorithms won't be tested again.

# OPTIONS

This tool accepts no tool specific options.

## References

[algorithm specifiers](common/alg.md) details the options for specifying
cryptographic algorithms _ALGORITHM_.

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.


# EXAMPLES

## Request testing of RSA algorithm

```bash
tpm2_incrementalselftest rsa
```

## Request testing of multiple algorithms

```bash
tpm2_incrementalselftest rsa ecc xor aes cbc
```

# NOTES

Algorithm suite specified can imply either testing the combination or the
complete suite, depending on TPM manufacturer implementation.

e.g : One TPM might only test AES with CTR mode if "aes ctr" is specified. An
other might also test complete AES mode list AND test ctr mode.

If an algorithm has already been tested, this command won't permit re-executing
the test. Only issuing **tpm2_selftest**(1) in full-test mode enabled will force
re-testing.

[returns](common/returns.md)

[footer](common/footer.md)
