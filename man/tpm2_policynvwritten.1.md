% tpm2_policynvwritten(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_policynvwritten**(1) - Restrict TPM object authorization to the written
state of an NV index.

# SYNOPSIS

**tpm2_policynvwritten** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_policynvwritten**(1) - Restricts TPM object authorization to the written
state of an NV index. Useful when creating write once NV indexes.

As an [*ARGUMENT*] it takes the expected written state of the NV index. It can
be specified as s|c|0|1.

# OPTIONS

  * **-S**, **\--session**=_FILE_:

    A session file from **tpm2_startauthsession**(1)'s **-S** option.

  * **-L**, **\--policy**=_FILE_:

    File to save the policy digest.

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

Create a write once NV index. To do this the NV index is defined with a write
policy that is valid only if the NV index attribute "TPMA_NV_WRITTEN" was never
set.

## Define the NV index write policy
```bash
tpm2_startauthsession -S session.dat
tpm2_policycommandcode -S session.dat TPM2_CC_NV_Write
tpm2_policynvwritten -S session.dat -L nvwrite.policy c
tpm2_flushcontext session.dat
```

## Define the NV index with the policy
```bash
 tpm2_nvdefine -s 1 -a "authread|policywrite" -p nvrdpass -L nvwrite.policy
```

## Write the NV index by satisfying the policy
```bash
tpm2_startauthsession -S session.dat --policy-session
tpm2_policycommandcode -S session.dat TPM2_CC_NV_Write
tpm2_policynvwritten -S session.dat c
echo 0xAA | xxd -r -p | tpm2_nvwrite 0x01000000 -i- -P session:session.dat
tpm2_flushcontext session.dat
```

[returns](common/returns.md)

[limitations](common/policy-limitations.md)

[footer](common/footer.md)
