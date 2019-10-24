% tpm2_policynamehash(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_policynamehash**(1) - Couples a policy with names of specific objects.

# SYNOPSIS

**tpm2_policynamehash** [*OPTIONS*]

# DESCRIPTION

**tpm2_policynamehash**(1) - Couples a policy with names of specific objects.
This is a deferred assertion where the hash of the names of all object handles
in a TPM command is checked against the one specified in the policy.

# OPTIONS

  * **-L**, **\--policy**=_FILE_:

    File to save the compounded policy digest.

  * **-S**, **\--session**=_FILE_:

    The policy session file generated via the **-S** option to
    **tpm2_startauthsession**(1).

  * **-n**, **\--name**=_FILE_:

    The file containing the name hash of the referenced objects.

## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

Restrict key duplication to specific new parent and specific duplicable key.

# Generate a duplicable object
```bash

openssl genrsa -out signing_key_private.pem 2048

openssl rsa -in signing_key_private.pem -out signing_key_public.pem -pubout

tpm2_loadexternal -G rsa -C o -u signing_key_public.pem -c signing_key.ctx \
-n signing_key.name

tpm2_startauthsession -S session.ctx -g sha256

tpm2_policyauthorize -S session.ctx -L authorized.policy -n signing_key.name

tpm2_policycommandcode -S session.ctx -L policy.dat TPM2_CC_Duplicate

tpm2_flushcontext session.ctx

tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx -Q

## The duplicable key
tpm2_create -Q -C primary.ctx -g sha256 -G rsa -r key.prv -u key.pub \
-L policy.dat -a "sensitivedataorigin|sign|decrypt"

tpm2_load -Q -C primary.ctx -r key.prv -u key.pub -c key.ctx
```

# Create the new parent
```bash

tpm2_create -Q -C primary.ctx -g sha256 -G rsa -r new_parent.prv \
-u new_parent.pub \
-a "decrypt|fixedparent|fixedtpm|restricted|sensitivedataorigin"

tpm2_loadexternal -Q -C o -u new_parent.pub -c new_parent.ctx
```

# Modify the duplicable key policy to namehash policy to restrict parent and key
```bash
tpm2_readpublic -Q -c new_parent.ctx -n new_parent.name

tpm2_readpublic -Q -c key.ctx -n key.name

cat key.name new_parent.name | openssl dgst -sha256 -binary > name.hash

tpm2_startauthsession -S session.ctx -g sha256

tpm2_policynamehash -L policy.namehash -S session.ctx -n name.hash

tpm2_flushcontext session.ctx

openssl dgst -sha256 -sign signing_key_private.pem \
-out policynamehash.signature policy.namehash

tpm2_startauthsession -S session.ctx -g sha256

tpm2_policyauthorize -S session.ctx -L authorized.policy -i policy.namehash \
-n signing_key.name

tpm2_policycommandcode -S session.ctx -L policy.dat TPM2_CC_Duplicate

tpm2_flushcontext session.ctx
```

# Satisfy the policy and attempt key duplication
```bash
tpm2_verifysignature -c signing_key.ctx -g sha256 -m policy.namehash \
-s policynamehash.signature -t verification.tkt -f rsassa

tpm2_startauthsession -S session.ctx --policy-session -g sha256

tpm2_policynamehash -S session.ctx -n name.hash

tpm2_policyauthorize -S session.ctx -i policy.namehash -n signing_key.name \
-t verification.tkt

tpm2_policycommandcode -S session.ctx TPM2_CC_Duplicate

tpm2_duplicate -C new_parent.ctx -c key.ctx -G null -p "session:session.ctx" \
-r dupprv.bin -s dupseed.dat

tpm2_flushcontext session.ctx
```

[returns](common/returns.md)

[limitations](common/policy-limitations.md)

[footer](common/footer.md)
