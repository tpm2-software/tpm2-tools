% tpm2_policypassword(1) tpm2-tools | General Commands Manual
%
% AUGUST 2018

# NAME

**tpm2_policypassword**(1) - Enables binding a policy to the authorization value
 of the authorized TPM object.

# SYNOPSIS

**tpm2_policypassword** [*OPTIONS*]

# DESCRIPTION

**tpm2_policypassword**(1) - Enables a policy that requires the object's
authentication passphrase be provided. This is equivalent to authenticating
using the object passphrase in plaintext, only this enforces it as a policy.
It provides a mechanism to allow for password authentication when an object only
allows policy based authorization, ie object attribute "userwithauth" is 0.
If using a resource manager (RM), then one supporting extended sessions, like
[tpm2-abrmd](https://github.com/tpm2-software/tpm2-abrmd) is required.

# OPTIONS

  * **-o**, **\--out-policy-file**=_POLICY\_FILE_:

    File to save the compounded policy digest.

  * **-S**, **\--session**=_SESSION_FILE_:

    The policy session file generated via the **-S** option to
    **tpm2_startauthsession**(1).

[common options](common/options.md)

[common tcti options](common/tcti.md)

[supported hash algorithms](common/hash.md)

[algorithm specifiers](common/alg.md)

# EXAMPLES

We want to authenticate using the TPM objects plaintext authentication value.
While we could authenticate with an ephermal password session, in this example
we will authenticate with the plaintext passphrase in  a policy session instead
using the **tpm2_policypassword**(1) tool.

## Create the password policy
```
tpm2_startauthsession -S session.dat

tpm2_policypassword -S session.dat -o policy.dat

tpm2_flushcontext -S session.dat
```

## Create the object with a passphrase and the password policy
```

tpm2_createprimary -a o -o prim.ctx

tpm2_create -g sha256 -G aes -u key.pub -r key.priv -C prim.ctx -L policy.pass \
  -p testpswd
```

## Authenticate with plaintext passphrase input
```
tpm2_load -C prim.ctx -u key.pub -r key.priv -n key.name -o key.ctx

tpm2_encryptdecrypt -c key.ctx -o encrypt.out -i plain.txt -p text
```

## Authenticate with password and the policy
```
tpm2_startauthsession \--policy-session -S session.dat

tpm2_policypassword -S session.dat -o policy.dat

tpm2_encryptdecrypt -c key.ctx -o encrypt.out -i plain.txt \
  -p session:session.dat+testpswd

tpm2_flushcontext -S session.dat
```

[returns](common/returns.md)

[footer](common/footer.md)
