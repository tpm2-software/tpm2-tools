% tpm2_policypcr(1) tpm2-tools | General Commands Manual
%
% JANUARY 2018

# NAME

**tpm2_policypcr**(1) - Perform a policyPCR event with the TPM.

# SYNOPSIS

**tpm2_policypcr** [*OPTIONS*]

# DESCRIPTION

**tpm2_policypcr**(1) generates a policy PCR event with the TPM. It is similar
to **tpm2_createpolicy**(1), however, it expects a session to be already
established via **tpm2_startauthsession**(1).

# OPTIONS

  * **-f**, **--policy-file**=_POLICY\_FILE_:
    File to save the policy digest.

  * **-F**, **--pcr-input-file**=_PCR\_FILE_:
    Optional Path or Name of the file containing expected pcr values for the
    specified index. Default is to read the current PCRs per the set list.

  * **-L**, **--set-list**=_PCR\_LIST_:
    The list of pcr banks and selected PCRs' ids (0~23) for each bank.

  * **-S**, **--session**=_SESSION_FILE_:

    The policy session file generated via the **-S** option to
    **tpm2_startauthsession**(1).

[common options](common/options.md)

[common tcti options](common/tcti.md)

[supported hash algorithms](common/hash.md)

[algorithm specifiers](common/alg.md)

# EXAMPLES

Starts a *trial* session, builds a PCR policy and uses that policy in the creation of an object.
Then, it uses a *policy* session to unseal some data stored in the object.
```
# Step 1: Create a trial session and build a PCR policy via a policyPCR event to generate
#   a policy hash.
#
# Step 2: Create an object and use the policy hash as the policy to satisfy for usage.
#
# Step 3: Create an actual policy session and using a policyPCR event, update the session
#  policy hash.
#
# Step 4: Using the actual policy session from step 3 in tpm2_unseal to unseal the object.
#

tpm2_createprimary -H e -g sha256 -G ecc -C primary.ctx

tpm2_pcrlist -Q -L "sha1:0,1,2,3 -o pcr.dat

handle=`tpm2_startauthsession -S session.dat | cut -d' ' -f 2-2`

tpm2_policypcr -Q -S session.dat -L "sha1:0,1,2,3" -F pcr.dat -f policy.dat

tpm2_flushcontext -H "$handle"

tpm2_create -Q -g sha256 -G keyedhash -u key.pub -r key.priv -C file:primary.ctx -L policy.dat \
  -A 'sign|fixedtpm|fixedparent|sensitivedataorigin' -I- <<< "12345678"

tpm2_load -Q -C file:primary.ctx -u key.pub -r key.priv -n unseal.key.name -o unseal.key.ctx

# Now that an object is created and a policy is required to access it, satisfy the policy on
# a session and use it to unseal the data stored in the object.

handle=`tpm2_startauthsession -a -S session.dat | cut -d' ' -f 2-2`

tpm2_policypcr -Q -S session.dat -L "sha1:0,1,2,3" -F pcr.dat -f policy.dat

unsealed=`tpm2_unseal -S session.dat -c unseal.key.ctx`

echo "$unsealed"

tpm2_flushcontext -H "$handle"
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
