% tpm2_policypcr(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_policypcr**(1) - Create a policy that includes specific PCR values.

# SYNOPSIS

**tpm2_policypcr** [*OPTIONS*]

# DESCRIPTION

**tpm2_policypcr**(1) - Generates a PCR policy event with the TPM. A PCR policy
event creates a policy bound to specific PCR values and is useful within larger
policies constructed using policyor and policyauthorize events. See
**tpm2_policyor(1)** and **tpm2_policyauthorize(1)** respectively for their
usages. The PCR data factored into the policy can be specified in one of 3 ways:
1. A file containing a concatenated list of PCR values as in the output from
   **tpm2_pcrread**.
2. Requiring the PCR values be read off the TPM by not specifying a PCR file
   input.
3. The digest of all the PCR values directly specified as an **argument**.

# OPTIONS

  * **-L**, **\--policy**=_FILE_:

    File to save the policy digest.

  * **-f**, **\--pcr**=_FILE_:

    Optional Path or Name of the file containing expected PCR values for the
    specified index. Default is to read the current PCRs per the set list.

  * **-l**, **\--pcr-list**=_PCR_:

    The list of PCR banks and selected PCRs' ids for each bank.  Forward
    sealing values can be specified.

  * **-S**, **\--session**=_FILE_:

    The policy session file generated via the **-S** option to
    **tpm2_startauthsession**(1).

  * **ARGUMENT**:
    The calculated digest of all PCR values specified as a hex byte stream.
    Eg: `openssl dgst -sha256 -binary pcr.bin | xxd -p -c 32`

## References

[context object format](common/ctxobj.md) details the methods for specifying
_OBJECT_.

[authorization formatting](common/authorizations.md) details the methods for
specifying _AUTH_.

[pcr bank specifiers](common/pcr.md) details the syntax for specifying pcr list
_PCR_.

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

Starts a *trial* session, builds a PCR policy and uses that policy in the
creation of an object. Then, it uses a *policy* session to unseal some data
stored in the object.

## Step 1: create a policy
```bash
tpm2_createprimary -C e -g sha256 -G ecc -c primary.ctx

tpm2_pcrread -o pcr.dat "sha1:0,1,2,3"

tpm2_startauthsession -S session.dat

tpm2_policypcr -S session.dat -l "sha1:0,1,2,3" -f pcr.dat -L policy.dat

tpm2_flushcontext session.dat
```

# Step 2: create an object using that policy
```bash
tpm2_create -Q -u key.pub -r key.priv -C primary.ctx -L policy.dat \
-i- <<< "12345678"

tpm2_load -C primary.ctx -u key.pub -r key.priv -n unseal.key.name \
-c unseal.key.ctx
```

## Step 3: Satisfy the policy
```bash
tpm2_startauthsession --policy-session -S session.dat

tpm2_policypcr -S session.dat -l "sha1:0,1,2,3" -f pcr.dat -L policy.dat
```

## Step 4: Use the policy
```bash
tpm2_unseal -psession:session.dat -c unseal.key.ctx
12345678

tpm2_flushcontext session.dat
```

[returns](common/returns.md)

[limitations](common/policy-limitations.md)

[footer](common/footer.md)
