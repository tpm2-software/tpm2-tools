% tpm2_policycountertimer(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_policycountertimer**(1) - Enables policy authorization by evaluating the
comparison operation on the TPM parameters time, clock, reset count, restart
count and TPM clock safe flag.

# SYNOPSIS

**tpm2_policycountertimer** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_policycountertimer**(1) - Enables policy authorization by evaluating the
comparison operation on the TPM parameters time, clock, reset count, restart
count and TPM clock safe flag. If time/clock, it is input as milliseconds value.
The parameter and the value is given as a command line argument as below:
```
tpm2_policycountertimer -S session.ctx safe
tpm2_policycountertimer -S session.ctx clock=<N ms>
tpm2_policycountertimer -S session.ctx time=<N ms>
tpm2_policycountertimer -S session.ctx resets=<N>
tpm2_policycountertimer -S session.ctx restarts=<N>
```
By default comparison tests for equality and also by default it tests for time.

# OPTIONS

  * **-L**, **\--policy**=_FILE_:

    File to save the policy digest.

  * **-S**, **\--session**=_FILE_:

    The policy session file generated via the **-S** option to
    **tpm2_startauthsession** or saved off of a previous tool run.

  * **--eq**

    if value of current time in the TPM = value of specified input time.

  * **--neq**

   if value of current time in the TPM != value of specified input time.

  * **--sgt**

   if signed value of current time in the TPM > signed value of specified input
   time.

  * **--ugt**

   if unsigned value of current time in the TPM > unsigned value of specified
   input time.

  * **--slt**

   if signed value of current time in the TPM < signed value of specified
   input time.

  * **--ult**

   if unsigned value of current time in the TPM < unsigned value of specified
   input time.

  * **--sge**

   if signed value of current time in the TPM >= signed value of specified
   input time.

  * **--uge**

   if unsigned value of current time in the TPM >= unsigned value of specified
   input time.

  * **--sle**

   if signed value of current time in the TPM <= unsigned value of specified
   input time.

  * **--ule**

   if unsigned value of current time in the TPM <= unsigned value of specified
   input time.

  * **--bs**

    if all bits set in value of current time in the TPM are set in value of
    specified input time.

  * **--bc**

    if all bits set in value of current time in the TPM are clear in value of
    specified input time.

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash.

## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

Create a sealing object with an authorization policy that evaluates only for
first minute of TPM restart.

## Create the policy and the sealing object

```bash
tpm2_startauthsession -S session.ctx

tpm2_policycountertimer -S session.ctx -L policy.countertimer --ult 60000

tpm2_flushcontext session.ctx

tpm2_createprimary -C o -c prim.ctx -Q

echo "SUPERSECRET" | \
tpm2_create -Q -u key.pub -r key.priv -i- -C prim.ctx \
-L policy.countertimer -a "fixedtpm|fixedparent" -c key.ctx
```

## Unsealing should work in the first minute after TPM restart

```bash
tpm2_startauthsession -S session.ctx --policy-session

tpm2_policycountertimer -S session.ctx --ult 60000

tpm2_unseal -c key.ctx -p session:session.ctx

tpm2_flushcontext session.ctx
```

[returns](common/returns.md)

[limitations](common/policy-limitations.md)

[footer](common/footer.md)
