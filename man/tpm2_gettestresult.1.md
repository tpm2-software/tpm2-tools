% tpm2_gettestresult(1) tpm2-tools | General Commands Manual
%
% JANUARY 2019

# NAME

**tpm2_gettestresult**(1) - Get the result of tests performed by the TPM

# SYNOPSIS

**tpm2_gettestresult** [*OPTIONS*]

# DESCRIPTION

**tpm2_gettestresult**(1) will return the result of the tests conducted by the TPM

Error code will state if the test executed successfully or have failed.

If pending algorithms are scheduled to be tested, **tpm2_gettestresult** will
return "TESTING". Otherwise "FAILED" will be returned or "SUCCESS" depending
on the result to the test.

Manufacturer-dependent information will also be printed in raw hex format.

# OPTIONS

This tool accepts no tool specific options.

[common options](common/options.md)

[common tcti options](common/tcti.md)

# EXAMPLES

## Get the result of the TPM testing

```
tpm2_gettestresult
```

# NOTES

This command is the one of the few commands authorized to be submitted to TPM when in failure mode.

# RETURNS

- 0 on success
- 1 on failure
- 2 on testing
- 3 on TPM failure

[footer](common/footer.md)
