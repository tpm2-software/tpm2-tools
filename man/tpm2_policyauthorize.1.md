% tpm2_policyauthorize(1) tpm2-tools | General Commands Manual
%
% AUGUST 2018

# NAME

**tpm2_policyauthorize**(1) - Generates/Creates a policy event that authorizes
a policy digest from TPM policy events.

# SYNOPSIS

**tpm2_policyauthorize** [*OPTIONS*]

# DESCRIPTION

**tpm2_policyauthorize**(1) - Generates a policy_authorize event with the TPM.
It expects a session to be already established via **tpm2_startauthsession**(1) and
requires extended session support with **tpm2-abrmd**.

1. If the input session is a trial session this tool generates a policy digest
that associates a signing authority's public key name with the policy being
authorized.

2. If the input session is real policy session **tpm2_policyauthorize**(1) looks
for a verification ticket from the TPM to attest that the TPM has verified
the signature on the policy digest before authorizing the policy
in the policy digest.

# OPTIONS

  * **-o**, **\--out-policy-file**=_POLICY\_FILE_:

    File to save the policy digest.

  * **-S**, **\--session**=_SESSION_FILE_:

    The policy session file generated via the **-S** option to
    **tpm2_startauthsession**(1).

  * **-i**, **\--in-policy-file**=_POLICY\_FILE_:

    The policy digest that has to be authorized.

  * **-q**, **\--qualify-data**=_DATA_FILE_:

    The policy qualifier data signed in conjunction with the input policy digest.
    This is a unique data that the signer can choose to include in the signature.

  * **-n**, **\--name**=_NAME\_DATA\_FILE_:

    File containing the name of the verifying public key. This ties the final
    policy digest with a signer. This can be retrieved with **tpm2_readpublic**(1)

  * **-t**, **\--ticket**=_TICKET\_FILE_:

    The ticket file to record the validation structure. This is generated with
    **tpm2_verifysignature**(1).

[common options](common/options.md)

[common tcti options](common/tcti.md)

[supported hash algorithms](common/hash.md)

[algorithm specifiers](common/alg.md)

# EXAMPLES

Starts a *trial* session, builds a PCR policy. This PCR policy digest is then
an input to the **tpm2_policyauthorize**(1) along with policy qualifier data and a
signer public. The resultant policy digest is then used in creation of objects.

Subsequently when the PCR change and so does the PCR policy digest, the actual
policy digest from the **tpm2_policyauthorize**(1) used in creation of the object
will not change. At runtime the new PCR policy needs to be satisfied along with
verification of the signature on the PCR policy digest using **tpm2_policyauthorize**(1)

## Create a signing authority
```
openssl genrsa -out signing_key_private.pem 2048

openssl rsa -in signing_key_private.pem -out signing_key_public.pem -pubout

tpm2_loadexternal -G rsa -a o -u signing_key_public.pem -o signing_key.ctx -n signing_key.name
```

## Create a policy to be authorized like a PCR policy
```
tpm2_pcrlist -L sha256:0 -o pcr0.sha256

tpm2_startauthsession -S session.ctx

tpm2_policypcr -S session.ctx -L sha256:0 -F pcr0.sha256 -o pcr.policy

tpm2_flushcontext -S session.ctx
```

## Sign the policy
```
openssl dgst -sha256 -sign signing_key_private.pem -out pcr.signature pcr.policy
```

## Authorize the policy in the policy digest
```
tpm2_startauthsession -S session.ctx

tpm2_policyauthorize -S session.ctx -i authorized.policy -o pcr.policy -n signing_key.name

tpm2_flushcontext -S session.ctx
```

## Create a TPM object like a sealing object with the authorized policy based authentication
```
tpm2_createprimary -Q -a o -g sha256 -G rsa -o prim.ctx

tpm2_create -Q -g sha256 -u sealing_pubkey.pub -r sealing_prikey.pub -i- -C prim.ctx -L authorized.policy <<< "secret to seal"
```

## Satisfy policy and unseal the secret
```
tpm2_verifysignature -c signing_key.ctx -g sha256 -m pcr.policy -s pcr.signature -t verification.tkt -f rsassa

tpm2_startauthsession \--policy-session -S session.ctx

tpm2_policypcr -Q -S session.ctx -L sha256:0 -o pcr.policy

tpm2_policyauthorize -S session.ctx -o authorized.policy -i pcr.policy -n signing_key.name -t verification.tkt

tpm2_load -Q -C prim.ctx -u sealing_pubkey.pub -r sealing_prikey.pub -o sealing_key.ctx

unsealed=$(tpm2_unseal -p"session:session.ctx" -c sealing_key.ctx)

echo $unsealed

tpm2_flushcontext -S session.ctx
```

[returns](common/returns.md)

[footer](common/footer.md)
