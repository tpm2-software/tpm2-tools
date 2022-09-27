% tpm2_policylocality(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_policylocality**(1) - Restrict TPM object authorization to specific
localities.

# SYNOPSIS

**tpm2_policylocality** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_policylocality**(1) - Restricts TPM object authorization to specific
TPM locality. Useful when you want to allow only specific locality
with the TPM object. A locality indicates the source of the command,
for example it could be from the application layer or the driver layer, each
would have it's own locality integer. Localities are hints to the TPM and are
enforced by the software communicating to the TPM. Thus they are
**not trusted** inputs on their own and are implemented in platform specific
ways.

As an argument it takes the _LOCALITY_ as an integer or friendly name.

Localities are fixed to a byte in size and have two representations, locality
and extended locality.

Localities 0 through 4 are the normal locality representation and are represented
as set bit indexes. Thus locality 0 is indicated by `1<<0` and locality 4 is
indicated by `1<<4`. Rather then using raw numbers, these localities can also
be specified by the friendly names of:
 - zero: locality 0 or `1<<0`
 - one: locality 1 or `1<<1`
 - two: locality 2 or `1<<2`
 - three: locality 3 or `1<<3`
 - four: locality 4 or `1<<4`

Anything from the range 32 - 255 are extended localities.

# OPTIONS

  * **-S**, **\--session**=_FILE_:

    A session file from **tpm2_startauthsession**(1)'s **-S** option.

  * **-L**, **\--policy**=_FILE_:

    File to save the policy digest.

  * **ARGUMENT** the command line argument specifies the locality number.

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

Start a *policy* session and extend it with a specific locality number (like 3).
Attempts to perform other operations would fail.

## Create an policy restricted by locality 3
```bash
tpm2_startauthsession -S session.dat

tpm2_policylocality -S session.dat -L policy.dat three

tpm2_flushcontext session.dat
```

## Create the object with auth policy
```bash
tpm2_createprimary -C o -c prim.ctx

tpm2_create -C prim.ctx -u sealkey.pub -r sealkey.priv -L policy.dat \
-i- <<< "SEALED-SECRET"
```

## Try unseal operation
```bash
tpm2_load -C prim.ctx -u sealkey.pub -r sealkey.priv -n sealkey.name \
-c sealkey.ctx

tpm2_startauthsession \--policy-session -S session.dat

tpm2_policylocality -S session.dat -L policy.dat three

# Change to locality 3, Note: this operation varies on different platforms

tpm2_unseal -p session:session.dat -c sealkey.ctx

tpm2_flushcontext session.dat
```

[returns](common/returns.md)

[limitations](common/policy-limitations.md)

[footer](common/footer.md)
