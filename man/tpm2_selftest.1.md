% tpm2_selftest(1) tpm2-tools | General Commands Manual
%
% JANUARY 2019

# NAME

**tpm2_selftest**(1) - Run TPM's self-test internal routines

# SYNOPSIS

**tpm2_selftest** [*OPTIONS*]

# DESCRIPTION

**tpm2_selftest**(1) - Cause the TPM to execute self-test of its capabilities.

Self-test can be executed in two modes :

* Simple test - TPM will test functions that require testing
* Full test - TPM will test all functions regardless of what has already been tested

# OPTIONS

* **-f**, **--fulltest** : Run self-test in full mode

[common options](common/options.md)

[common tcti options](common/tcti.md)

# EXAMPLES

## Perform a simple TPM self-test
```
tpm2_selftest
```

## Perform a complete TPM self-test
```
tpm2_selftest -f
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
