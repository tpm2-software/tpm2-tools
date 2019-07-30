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
real policy session **tpm2_policyor**(1) authenticates the object successfully if
at least one of the policy events are true.

# OPTIONS

  * **-L**, **\--policy**=_POLICY\_FILE_:

    File to save the compounded policy digest.

  * **-l**, **\--policy-list**=_POLICY\_FILE_\_LIST:

    The list of files for the policy digests that has to be compounded resulting
    in individual policies being added to final policy digest that can
    authenticate the object. The list begins with the policy digest hash alg.

  * **-S**, **\--session**=_SESSION_FILE_:

    The policy session file generated via the **-S** option to
    **tpm2_startauthsession**(1).

[common options](common/options.md)

[common tcti options](common/tcti.md)

[supported hash algorithms](common/hash.md)

[algorithm specifiers](common/alg.md)

# EXAMPLES

Creates two sets of PCR data files, one of them being the existing PCR values
and other being a set of PCR values that would result if the PCR were extended
with a known value (without actually extending the PCR). Now create two separate
policy digests, each with one set of the PCR values using **tpm2_policypcr**(1) tool
in *trial* sessions. Now build a policy_or with the two PCR policy digests as
inputs. Create a sealing object with an authentication policy resulting from
**tpm2_policyor**(1)
and seal a secret. Unsealing with either of the PCR sets should be successful.

## Create two PCR sets and policies
```bash
tpm2_pcrread -oset1_pcr0.sha1 sha1:0

tpm2_startauthsession -S session.ctx

tpm2_policypcr -S session.ctx -l sha1:0 -f set1_pcr0.sha1 -L set1_pcr0.policy

tpm2_flushcontext session.ctx

dd if=/dev/urandom of=rand.bin bs=1 count=20

cat set1_pcr0.sha1 rand.bin | openssl dgst -sha1 -binary -out set2_pcr0.sha1

tpm2_startauthsession -S session.ctx

tpm2_policypcr -S session.ctx -l sha1:0 -f set2_pcr0.sha1 -L set2_pcr0.policy

tpm2_flushcontext session.ctx
```

## Generate a policy by compounding valid policies
```bash
tpm2_startauthsession -S session.ctx

tpm2_policyor -S session.ctx -L policy.or -l sha256:set1_pcr0.policy,set2_pcr0.policy

tpm2_flushcontext session.ctx
```

## Create a TPM sealing object with the compounded auth policy
```bash
tpm2_createprimary -C o -g sha256 -G rsa -c prim.ctx

tpm2_create -u sealing_key.pub -r sealing_key.priv -i- -C prim.ctx -L policy.or <<< "secret to seal"

tpm2_load -C prim.ctx -u sealing_key.pub -r sealing_key.priv -c sealing_key.ctx
```

## Satisfy the policy and unseal the secret
```bash
tpm2_startauthsession \--policy-session -S session.ctx

tpm2_policypcr -Q -S session.ctx -l sha1:0 -L o_set1_pcr0.policy

tpm2_policyor -S session.ctx -L policy.or -l sha256:set1_pcr0.policy,set2_pcr0.policy

tpm2_unseal -p"session:session.ctx" -c sealing_key.ctx
secret to seal

tpm2_flushcontext session.ctx
```

[returns](common/returns.md)

[limitations](common/policy-limitations.md)

[footer](common/footer.md)
