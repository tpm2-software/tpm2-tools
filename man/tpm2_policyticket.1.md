% tpm2_ticket(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_ticket**(1) - Enables policy authorization by verifying a ticket that
represents a validated authorization that had an expiration time associated
with it.

# SYNOPSIS

**tpm2_ticket** [*OPTIONS*]

# DESCRIPTION

**tpm2_ticket**(1) - Enables policy authorization by verifying a ticket that
represents a validated authorization that had an expiration time associated with
it.

# OPTIONS

  * **-L**, **\--policy**=_FILE_:

    File to save the compounded policy digest.

  * **-S**, **\--session**=_FILE_:

    The policy session file generated via the **-S** option to
    **tpm2_startauthsession**(1).

  * **-n**, **\--name**=_FILE_:

    Name of the object that validated the authorization.

  * **\--ticket**=_FILE_:

    The ticket file to record the authorization ticket structure.

  * **\--timeout**=_FILE_:

    The file path to record the timeout structure returned.

  * **-q**, **\--qualification**=_FILE\_OR\_HEX\_STR_:

    Optional, the policy qualifier data that the signer can choose to include in the
    signature. Can be either a hex string or path.

## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

Authorize a TPM operation on an object whose authorization is bound to specific
signing authority.

## Create the signing authority and load the verification key
```bash
openssl genrsa -out private.pem 2048

openssl rsa -in private.pem -outform PEM -pubout -out public.pem

tpm2_loadexternal -C o -G rsa -u public.pem -c signing_key.ctx \
-n signing_key.name
```

## Generate signature with the expiry time
```bash
EXPIRYTIME="FFFFFE0C"

echo $EXPIRYTIME | xxd -r -p | \
openssl dgst -sha256 -sign private.pem -out signature.dat
```

## Create the policy
```bash
tpm2_startauthsession -S session.ctx

tpm2_policysigned -S session.ctx -g sha256 -s signature.dat -f rsassa \
-c signing_key.ctx -L policy.signed

tpm2_flushcontext session.ctx
```

## Create a sealing object
```bash
tpm2_createprimary -C o -c prim.ctx -Q

echo "plaintext" > secret.dat

tpm2_create -u sealing_key.pub -r sealing_key.priv -c sealing_key.ctx \
-C prim.ctx -i secret.dat -L policy.signed -Q
```

## Create ticket-able policy
```bash
tpm2_startauthsession -S session.ctx --nonce-tpm=nonce.test --policy-session

{ cat nonce.test & echo $EXPIRYTIME | xxd -r -p; } | \
openssl dgst -sha256 -sign private.pem -out signature.dat

tpm2_policysigned -S session.ctx -g sha256 -s signature.dat -f rsassa \
-c signing_key.ctx -x nonce.test --ticket tic.ket --timeout time.out \
-t 0xFFFFFE0C

tpm2_flushcontext session.ctx
```

##Test with policyticket instead of policysigned
```bash
tpm2_startauthsession -S session.ctx --policy-session

tpm2_policyticket -S session.ctx -n signing_key.name --ticket tic.ket \
--timeout time.out

tpm2_unseal -p session:session.ctx -c sealing_key.ctx
```

[returns](common/returns.md)

[limitations](common/policy-limitations.md)

[footer](common/footer.md)
