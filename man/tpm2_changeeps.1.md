% tpm2_changeeps(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_changeeps**(1) - Replaces the active endorsement primary seed with a new
one generated off the TPM2 RNG.

# SYNOPSIS

**tpm2_changeeps** [*OPTIONS*]

# DESCRIPTION

**tpm2_changeeps**(1) - Replaces the active endorsement primary seed with a new
one generated off the TPM2 RNG. The Transient and Persistent objects under the
endorsement hierarchy are lost. This command requires platform auth.

# OPTIONS

  * **-p**, **\--auth** specifies the _AUTH_ for the platform.
  hierarchy.

## References

[authorization formatting](common/authorizations.md) details the methods for
specifying _AUTH_.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

## Change the endorsement primary seed where the platform auth is NULL.
```bash
tpm2_changeeps
```

[returns](common/returns.md)

[limitations](common/policy-limitations.md)

[footer](common/footer.md)
