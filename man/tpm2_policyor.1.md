% tpm2_policyor(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_policyor**(1) - logically OR's two policies together.

# SYNOPSIS

**tpm2_policyor** [*OPTIONS*]

# DESCRIPTION

**tpm2_policyor**(1) - Generates a policy_or event with the TPM. It expects a
session to be already established via **tpm2_startauthsession**(1). If
the input session is a trial session this tool generates a policy digest that
compounds two or more input  policy digests such that the resulting policy digest
requires at least one of the policy events being true. If the input session is
real policy session **tpm2_policyor**(1) authenticates the object successfully
if at least one of the policy events are true.

# OPTIONS

  * **-L**, **\--policy**=_FILE_:

    File to save the compounded policy digest.

  * **-l**, **\--policy-list**=_POLICY\_FILE_\_LIST:

    The list of files for the policy digests that has to be compounded resulting
    in individual policies being added to final policy digest that can
    authenticate the object. The list begins with the policy digest hash alg.

  * **-S**, **\--session**=_FILE_:

    The policy session file generated via the **-S** option to
    **tpm2_startauthsession**(1).

## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

Creates two sets of PCR data files, one of them being the existing PCR values
and other being a set of PCR values that would result if the PCR were extended
with a known value. Now create two separate policy digests, each with one set
of the PCR values using **tpm2_policypcr**(1) tool in *trial* sessions. Now
build a policy_or with the two PCR policy digests as inputs. Create a sealing
object with an authentication policy compounding the 2 policies with
**tpm2_policyor** and seal a secret. Unsealing with either of the PCR sets
should be successful.

## Create two unique pcr policies with corresponding unique sets of pcrs.

### Start with pcr value 0
```bash
tpm2_pcrreset 23
```

### PCR1 policy
```bash
tpm2_startauthsession -S session.ctx

tpm2_policypcr -S session.ctx -l sha1:23 -L set1.pcr0.policy

tpm2_flushcontext session.ctx

rm session.ctx
```

### PCR2 policy
```bash
tpm2_pcrextend 23:sha1=f1d2d2f924e986ac86fdf7b36c94bcdf32beec15

tpm2_startauthsession -S session.ctx

tpm2_policypcr -S session.ctx -l sha1:23 -L set2.pcr0.policy

tpm2_flushcontext session.ctx

rm session.ctx
```

## Create a policyOR resulting from compounding the two unique pcr policies in an OR fashion
```bash
tpm2_startauthsession -S session.ctx

tpm2_policyor -S session.ctx -L policyOR \
-l sha256:set1.pcr0.policy,set2.pcr0.policy

tpm2_flushcontext session.ctx

rm session.ctx
```

## Create a sealing object with auth policyOR created above.
```bash
tpm2_createprimary -C o -c prim.ctx

tpm2_create -g sha256 -u sealkey.pub -r sealkey.priv -L policyOR -C prim.ctx \
-i- <<< "secretpass"

tpm2_load -C prim.ctx -c sealkey.ctx -u sealkey.pub -r sealkey.priv
```

## Attempt unsealing by satisfying the policyOR by satisfying SECOND of the two policies.
```bash
tpm2_startauthsession -S session.ctx --policy-session

tpm2_policypcr -S session.ctx -l sha1:23

tpm2_policyor -S session.ctx -L policyOR \
-l sha256:set1.pcr0.policy,set2.pcr0.policy

unsealed=`tpm2_unseal -p session:session.ctx -c sealkey.ctx`

echo $unsealed

tpm2_flushcontext session.ctx

rm session.ctx
```

## Extend the pcr to emulate tampering of the system software and hence the pcr value.
```bash
tpm2_pcrextend 23:sha1=f1d2d2f924e986ac86fdf7b36c94bcdf32beec15
```

## Attempt unsealing by trying to satisy the policOR by attempting to satisy one of the two policies.
```bash
tpm2_startauthsession -S session.ctx --policy-session

tpm2_policypcr -S session.ctx -l sha1:23
```

### This should fail
```bash
tpm2_policyor -S session.ctx -L policyOR \
-l sha256:set1.pcr0.policy,set2.pcr0.policy

tpm2_flushcontext session.ctx

rm session.ctx
```

## Reset pcr to get back to the first set of pcr value
```bash
tpm2_pcrreset 23
```

## Attempt unsealing by satisfying the policyOR by satisfying FIRST of the two policies.
```bash
tpm2_startauthsession -S session.ctx --policy-session

tpm2_policypcr -S session.ctx -l sha1:23

tpm2_policyor -S session.ctx -L policyOR \
-l sha256:set1.pcr0.policy,set2.pcr0.policy

unsealed=`tpm2_unseal -p session:session.ctx -c sealkey.ctx`

echo $unsealed

tpm2_flushcontext session.ctx

rm session.ctx
```

[returns](common/returns.md)

[limitations](common/policy-limitations.md)

[footer](common/footer.md)
