% tpm2_getpolicydigest(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_getpolicydigest**(1) - Retrieves the policy digest from session.

# SYNOPSIS

**tpm2_getpolicydigest** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_getpolicydigest**(1) - Returns the policydigest of a session.

Output defaults to *stdout* and binary format unless otherwise specified with
**-o** and **--hex** options respectively.

# OPTIONS

  * **-o**, **\--output**=_FILE_

    Specifies the filename to output the raw bytes to. Defaults to stdout as a
    hex string.

  * **\--hex**

	Convert the output data to hex format without a leading "0x".

  * **-S**, **\--session**=_FILE_:

    The session created using **tpm2_startauthsession**.

## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

## Create a session and retrieve policydigest
```bash
tpm2 startauthsession -S session.ctx
tpm2 policypassword -S session.ctx -L test.policy
tpm2 getpolicydigest -S session.ctx -o policy.out
tpm2 flushcontext session.ctx
```


[returns](common/returns.md)

[footer](common/footer.md)
