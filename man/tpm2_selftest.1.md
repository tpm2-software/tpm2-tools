% tpm2_selftest(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_selftest**(1) - Run TPM's self-test internal routines

# SYNOPSIS

**tpm2_selftest** [*OPTIONS*]

# DESCRIPTION

**tpm2_selftest**(1) - Cause the TPM to execute self-test of its capabilities.

Self-test can be executed in two modes :

* Simple test - TPM will test functions that require testing
* Full test - TPM will test all functions regardless of what has already been
tested

Once the TPM receives this request, the TPM will return TPM\_RC\_TESTING for any
command that requires a test. If a test fails, the TPM will return
TPM\_RC\_FAILURE for any command other than TPM2\_GetTestResult() and
TPM2\_GetCapability() during this time. The TPM will remain in failure mode
until the next TPM initialization.

# OPTIONS

* **-f**, **\--fulltest** : Run self-test in full mode

## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

## Perform a simple TPM self-test
```bash
tpm2_selftest
```

## Perform a complete TPM self-test
```bash
tpm2_selftest -f
```

[returns](common/returns.md)

[footer](common/footer.md)
