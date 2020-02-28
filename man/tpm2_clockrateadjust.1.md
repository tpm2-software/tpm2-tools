% tpm2_clockrateadjust(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_clockrateadjust**(1) - Sets the clock rate period on the TPM.

# SYNOPSIS

**tpm2_clockrateadjust** [*OPTIONS*] __ADJUSTER__

# DESCRIPTION

**tpm2_clockrateadjust**(1) - Adjusts the rate at which clock and time are updated on
the TPM so one can better match real time. With no argument, the command is invoked
but the clock rate is not altered. With an argument, the tool will adjust the clock
and time period. The command can either increase or decrease the clock period via 3
distinct granularities: course, medium and fine. To specify this, the argument can
be a string of 1 to 3 characters of *all* 's' or 'f'.

## Valid Adjuster Arguments

  * s - slows down the clock period one fine increment.
  * ss - slows down the clock period one medium increment.
  * sss - slows down the clock period one course increment.
  * f - speeds up the clock period one fine increment.
  * ff - speeds up the clock period one medium increment.
  * fff - speeds up the clock period one course increment.

# OPTIONS

  * **-c**, **\--hierarchy**=_OBJECT_:

    The hierarchy to use for authorization, either platform or owner.
    Defaults to the owner hierarchy if not specified.

  * **-p**, **\--auth**=_AUTH_:

    Specifies the authorization value for the hierarchy specified by option
    **-c**.

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash.

## References

[context object format](common/ctxobj.md) details the methods for specifying
_OBJECT_.

[authorization formatting](common/authorizations.md) details the methods for
specifying _AUTH_.

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

## Set the clock

Slow the clock one medium increment using the owner password.

```bash
tpm2_clockrateadjust -p ownerpw ss
```

Speed up the clock one course increment using the platform password.

```bash
tpm2_clockrateadjust -c p -p platformpw fff
```

[returns](common/returns.md)

[footer](common/footer.md)
