% tpm2_policyor(1) tpm2-tools | General Commands Manual
%
% AUGUST 2018

# NAME

**tpm2_policyor**(1) - Generates/Creates a policy event that compounds two or
more input policy digests such that the resulting authentication is successful
with at least one of the policy events being true.

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

  * **-o**, **\--out-policy-file**=_POLICY\_FILE_:

    File to save the compounded policy digest.

  * **-L**, **\--policy-list**=_POLICY\_FILE_\_LIST:

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
```
tpm2_pcrlist -L sha1:0 -o set1_pcr0.sha1

tpm2_startauthsession -S session.ctx

tpm2_policypcr -S session.ctx -L sha1:0 -F set1_pcr0.sha1 -o set1_pcr0.policy

tpm2_flushcontext -S session.ctx

dd if=/dev/urandom of=rand.bin bs=1 count=20

cat set1_pcr0.sha1 rand.bin | openssl dgst -sha1 set2_pcr0.sha1

tpm2_startauthsession -S session.ctx

tpm2_policypcr -S session.ctx -L sha1:0 -F set2_pcr0.sha1 -o set2_pcr0.policy

tpm2_flushcontext -S session.ctx
```

## Generate a policy by compounding valid policies
```
tpm2_startauthsession -S session.ctx

tpm2_policyor -S session.ctx -o policy.or -L sha256:set1_pcr0.policy,set2_pcr0.policy

tpm2_flushcontext -S session.ctx
```

## Create a TPM sealing object with the compounded auth policy
```
tpm2_createprimary -Q -a o -g sha256 -G rsa -o prim.ctx

tpm2_create -Q -g sha256 -u sealing_key.pub -r sealing_key.pub -i- -C prim.ctx -L policy.or <<< "secret to seal"
```

## Satisfy the policy and unseal the secret
```
tpm2_startauthsession \--policy-session -S session.ctx

tpm2_policypcr -Q -S session.ctx -L sha1:0 -o o_set1_pcr0.policy

tpm2_policyor -S session.ctx -o policy.or -L sha256:set1_pcr0.policy,set2_pcr0.policy

unsealed=`tpm2_unseal -p"session:session.ctx" -c sealing_key.ctx

tpm2_flushcontext -S session.ctx
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
