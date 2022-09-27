% tpm2_policypassword(1) tpm2-tools | General Commands Manual

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

# OPTIONS

  * **-L**, **\--policy**=_FILE_:

    File to save the compounded policy digest.

  * **-S**, **\--session**=_FILE_:

    The policy session file generated via the **-S** option to
    **tpm2_startauthsession**(1).

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

We want to authenticate using the TPM objects plaintext authentication value.
While we could authenticate with an ephemeral password session, in this example
we will authenticate with the plaintext passphrase in  a policy session instead
using the **tpm2_policypassword**(1) tool.

## Create the password policy
```bash
tpm2_startauthsession -S session.dat

tpm2_policypassword -S session.dat -L policy.dat

tpm2_flushcontext session.dat
```

## Create the object with a passphrase and the password policy
```bash
tpm2_createprimary -C o -c prim.ctx

tpm2_create -g sha256 -G aes -u key.pub -r key.priv -C prim.ctx -L policy.dat \
  -p testpswd
```

## Authenticate with plaintext passphrase input
```bash
tpm2_load -C prim.ctx -u key.pub -r key.priv -n key.name -c key.ctx

echo "plaintext" > plain.txt
tpm2_encryptdecrypt -c key.ctx -o encrypt.out plain.txt -p testpswd plain.txt
```

## Authenticate with password and the policy
```bash
tpm2_startauthsession \--policy-session -S session.dat

tpm2_policypassword -S session.dat -L policy.dat

tpm2_encryptdecrypt -c key.ctx -o encrypt.out \
  -p session:session.dat+testpswd plain.txt

tpm2_flushcontext session.dat
```

[returns](common/returns.md)

[limitations](common/policy-limitations.md)

[footer](common/footer.md)
