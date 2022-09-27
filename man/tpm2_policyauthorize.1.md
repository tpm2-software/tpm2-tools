% tpm2_policyauthorize(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_policyauthorize**(1) - Allows for mutable policies by tethering to a
signing authority.

# SYNOPSIS

**tpm2_policyauthorize** [*OPTIONS*]

# DESCRIPTION

**tpm2_policyauthorize**(1) - This command allows for policies to change by associating
the policy to a signing authority and allowing the policy contents to change.

1. If the input session is a trial session this tool generates a policy digest
that associates a signing authority's public key name with the policy being
authorized.

2. If the input session is real policy session **tpm2_policyauthorize**(1) looks
for a verification ticket from the TPM to attest that the TPM has verified
the signature on the policy digest before authorizing the policy
in the policy digest.

# OPTIONS

  * **-L**, **\--policy**=_FILE_:

    File to save the policy digest.

  * **-S**, **\--session**=_FILE_:

    The policy session file generated via the **-S** option to
    **tpm2_startauthsession**(1).

  * **-i**, **\--input**=_FILE_:

    The policy digest that has to be authorized.

  * **-q**, **\--qualification**=_FILE\_OR\_HEX_:

    The policy qualifier data signed in conjunction with the input policy digest.
    This is unique data that the signer can choose to include in the signature
    and can either be a path or hex string.

  * **-n**, **\--name**=_FILE_:

    File containing the name of the verifying public key. This ties the final
    policy digest with a signer. This can be retrieved with
    **tpm2_readpublic**(1)

  * **-t**, **\--ticket**=_FILE_:

    The ticket file to record the validation structure. This is generated with
    **tpm2_verifysignature**(1).

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

Starts a *trial* session, builds a PCR policy. This PCR policy digest is then
an input to the **tpm2_policyauthorize**(1) along with policy qualifier data and
a signer public. The resultant policy digest is then used in creation of objects.

Subsequently when the PCR change and so does the PCR policy digest, the actual
policy digest from the **tpm2_policyauthorize**(1) used in creation of the object
will not change. At runtime the new PCR policy needs to be satisfied along with
verification of the signature on the PCR policy digest using **tpm2_policyauthorize**(1)

## Create a signing authority
```bash
openssl genrsa -out signing_key_private.pem 2048

openssl rsa -in signing_key_private.pem -out signing_key_public.pem -pubout

tpm2_loadexternal -G rsa -C o -u signing_key_public.pem -c signing_key.ctx -n signing_key.name
```

## Create the authorize policy digest
```bash
tpm2_startauthsession -S session.ctx

tpm2_policyauthorize -S session.ctx -L authorized.policy -n signing_key.name

tpm2_flushcontext session.ctx
```

## Create a policy to be authorized like a PCR policy
```bash
tpm2_pcrread -opcr0.sha256 sha256:0

tpm2_startauthsession -S session.ctx

tpm2_policypcr -S session.ctx -l sha256:0 -f pcr0.sha256 -L pcr.policy_desired

tpm2_flushcontext session.ctx
```

## Sign the policy
```bash
openssl dgst -sha256 -sign signing_key_private.pem -out pcr.signature pcr.policy_desired
```

## Create a TPM object like a sealing object with the authorized policy based authentication
```bash
tpm2_createprimary -C o -g sha256 -G rsa -c prim.ctx

tpm2_create -g sha256 -u sealing_pubkey.pub -r sealing_prikey.pub -i- -C prim.ctx -L authorized.policy <<< "secret to seal"
```

## Verify the desired policy digest comes from the signing authority, read the actual value of PCR and check that read policy and desired policy are equal. 
```bash
tpm2_verifysignature -c signing_key.ctx -g sha256 -m  pcr.policy_desired -s pcr.signature -t verification.tkt -f rsassa

tpm2_startauthsession \--policy-session -S session.ctx

tpm2_policypcr -S session.ctx -l sha256:0 -L pcr.policy_read

tpm2_policyauthorize -S session.ctx -L authorized.policy -i pcr.policy_desired -n signing_key.name -t verification.tkt

tpm2_load -C prim.ctx -u sealing_pubkey.pub -r sealing_prikey.pub -c sealing_key.ctx

unsealed=$(tpm2_unseal -p"session:session.ctx" -c sealing_key.ctx)

echo $unsealed

tpm2_flushcontext session.ctx
```

[returns](common/returns.md)

[limitations](common/policy-limitations.md)

[footer](common/footer.md)
