% tpm2_policyauthorize(1) tpm2-tools | General Commands Manual
%
% AUGUST 2018

# NAME

**tpm2_policyauthorize**(1) - Generates/Creates a policy event that authorizes
a policy digest from TPM policy events.

# SYNOPSIS

**tpm2_policyauthorize** [*OPTIONS*]

# DESCRIPTION

**tpm2_policyauthorize**(1) Generates a policy_authorize event with the TPM. It
expects a session to be already established via **tpm2_startauthsession**(1). If
the input session is a trial session this tool generates a policy digest that
associates a signing authority's public key name with the policy being
authorized. If the input session is real policy session **tpm2_policyauthorize**
looks for a verification ticket from the TPM to attest that the TPM has verified
the signature on the policy digest.

# OPTIONS

  * **-o**, **--policy-file**=_POLICY\_FILE_:

    File to save the policy digest.

  * **-S**, **--session**=_SESSION_FILE_:

    The policy session file generated via the **-S** option to
    **tpm2_startauthsession**(1).

  * **-f**, **--input-policy-file**=_POLICY\_FILE_:

    The policy digest that has to be authorized.

  * **-q**, **--qualifier**=_DATA_FILE_:

    The policy qualifier data signed in conjunction with the input policy digest.
    This is a unique data that the signer can choose to include in the signature.

  * **-n**, **--name**=_NAME\_DATA\_FILE_:

    File containing the name of the verifying public key. This ties the final
    policy digest with a signer. This can be retrieved with **tpm2_readpublic**

  * **-t**, **--ticket**=_TICKET\_FILE_:

    The ticket file to record the validation structure. This is generated with
    **tpm2_verifysignature**.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[supported hash algorithms](common/hash.md)

[algorithm specifiers](common/alg.md)

# EXAMPLES

Starts a *trial* session, builds a PCR policy. This pcr policy digest is then
an input to the **tpm2_policyauthorize** along with policy qualifier data and a
signer public. The resultant policy digest is then used in creation of objects.
Subsequently when the PCR change and so does the pcr policy digest, the actual
policy digest from the **tpm2_policyauthorize** used in creation of the object
will not change. At runtime the new pcr policy needs to be satisfied along with
verification of the signature on the pcr policy digest using **tpm2_policyauthorize**
```
(1) Create a policy to be authorized like pcr policy:
tpm2_pcrlist  -L sha256:0 -o file_pcr_value
tpm2_startauthsession  -S file_session_file
tpm2_policypcr  -S file_session_file -L sha256:0 -F file_pcr_value -f pcr_policy
tpm2_flushcontext -S file_session_file

(2)Generate an authorized policy for the policy:
tpm2_startauthsession  -S file_session_file
tpm2_policyauthorize  -S file_session_file -o final_policy -f pcr_policy \
  -q policy_qualifier -n verifying_public_key_name
tpm2_flushcontext -S file_session_file

(3)Create a sealing object with policyauthorize as the sealing auth policy:
tpm2_createprimary -Q -a o -g sha256 -G rsa -o prim.ctx
tpm2_create -Q -g sha256 -u sealing_key.pub -r sealing_key.pub -I- -C prim.ctx \
  -L final_policy -A 'fixedtpm|fixedparent' <<< "secret to seal"

(4)Satisfy policy and unseal secret data:
tpm2_startauthsession -a -S real_policy_session_policyAuthorize
tpm2_policypcr -Q -S real_policy_session_policyAuthorize -L sha256:0 \
  -F file_pcr_value -f pcr_policy
tpm2_policyauthorize  -S file_session_file -o final_policy -f pcr_policy \
  -q policy_qualifier -n verifying_public_key_name -t verification_ticket
unsealed=`tpm2_unseal -p"session:real_policy_session_policyAuthorize" \
  -c sealing_key.ctx
tpm2_flushcontext -S file_session_file
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
