% tpm2_policycphash(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_policycphash**(1) - Couples a policy with command parameters of the
command.

# SYNOPSIS

**tpm2_policycphash** [*OPTIONS*]

# DESCRIPTION

**tpm2_policycphash**(1) - Couples a policy with command parameters of the
command. This is a deferred assertion where the hash of the command parameters
in a TPM command is checked against the one specified in the policy.

# OPTIONS

  * **-L**, **\--policy**=_FILE_:

    File to save the compounded policy digest.

  * **-S**, **\--session**=_FILE_:

    The policy session file generated via the **-S** option to
    **tpm2_startauthsession**(1).

  * **\--cphash-input**=_FILE_:

    The file containing the command parameter hash of the command.

  * **\--cphash**=_FILE_:

    **DEPRECATED**, use **--cphash-input** instead.

## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

Restrict the value that can be set through tpm2_nvsetbits.

## Define NV index object with authorized policy
```bash
openssl genrsa -out signing_key_private.pem 2048
openssl rsa -in signing_key_private.pem -out signing_key_public.pem -pubout
tpm2_loadexternal -G rsa -C o -u signing_key_public.pem -c signing_key.ctx \
-n signing_key.name
tpm2_startauthsession -S session.ctx -g sha256
tpm2_policyauthorize -S session.ctx -L authorized.policy -n signing_key.name
tpm2_flushcontext session.ctx
tpm2_nvdefine 1 -a "policywrite|authwrite|ownerread|nt=bits" -L authorized.policy
```

## Create policycphash
```bash
tpm2_nvsetbits 1 -i 1 --cphash cp.hash
tpm2_startauthsession -S session.ctx -g sha256
tpm2_policycphash -S session.ctx -L policy.cphash --cphash cp.hash
tpm2_flushcontext session.ctx
```

## Sign and verify policycphash
```bash
openssl dgst -sha256 -sign signing_key_private.pem \
-out policycphash.signature policy.cphash
tpm2_verifysignature -c signing_key.ctx -g sha256 -m policy.cphash \
-s policycphash.signature -t verification.tkt -f rsassa
```

## Satisfy policycphash and execute nvsetbits
```bash
tpm2_startauthsession -S session.ctx --policy-session -g sha256
tpm2_policycphash -S session.ctx --cphash cp.hash
tpm2_policyauthorize -S session.ctx -i policy.cphash -n signing_key.name \
-t verification.tkt
tpm2_nvsetbits 1 -i 1 -P "session:session.ctx"
tpm2_flushcontext session.ctx
```

[returns](common/returns.md)

[limitations](common/policy-limitations.md)

[footer](common/footer.md)
