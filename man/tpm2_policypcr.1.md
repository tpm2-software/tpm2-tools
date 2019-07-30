% tpm2_policypcr(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_policypcr**(1) - Create a policy that includes specific PCR values.

# SYNOPSIS

**tpm2_policypcr** [*OPTIONS*]

# DESCRIPTION

**tpm2_policypcr**(1) - Generates a PCR policy event with the TPM. A PCR policy event
creates a policy bound to specific PCR values and is useful within larger policies
constructed using policyor and policyauthorize events. See **tpm2_policyor(1)**
and **tpm2_policyauthorize(1)** respectively for their usages.

# OPTIONS

  * **-L**, **\--policy**=_POLICY\_FILE_:

    File to save the policy digest.

  * **-f**, **\--pcr**=_PCR\_FILE_:

    Optional Path or Name of the file containing expected PCR values for the
    specified index. Default is to read the current PCRs per the set list.

  * **-l**, **\--pcr-list**=_PCR\_LIST_:

    The list of PCR banks and selected PCRs' ids for each bank.

  * **-S**, **\--session**=_SESSION_FILE_:

    The policy session file generated via the **-S** option to
    **tpm2_startauthsession**(1).

[common options](common/options.md)

[common tcti options](common/tcti.md)

[supported hash algorithms](common/hash.md)

[algorithm specifiers](common/alg.md)

# EXAMPLES

Starts a *trial* session, builds a PCR policy and uses that policy in the creation of an object.
Then, it uses a *policy* session to unseal some data stored in the object.

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
tpm2_create -Q -u key.pub -r key.priv -C primary.ctx -L policy.dat -i- <<< "12345678"

tpm2_load -C primary.ctx -u key.pub -r key.priv -n unseal.key.name -c unseal.key.ctx
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
