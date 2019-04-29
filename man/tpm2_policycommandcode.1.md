% tpm2_policycommandcode(1) tpm2-tools | General Commands Manual
%
% JANUARY 2018

# NAME

**tpm2_policycommandcode**(1) - Restrict TPM object authorization to specific
TPM commands or operations.

# SYNOPSIS

**tpm2_policycommandcode** [*OPTIONS*] _COMMAND\_CODE_

# DESCRIPTION

**tpm2_policycommandcode**(1) - Restricts TPM object authorization to specific
TPM commands or operations. Useful when you want to allow only specific commands
with the TPM object. As an argument it takes the _COMMAND\_CODE_ as an integer
value. Requires support for extended sessions with resource manager.

# OPTIONS

  * **-S**, **\--session**=_SESSION\_FILE_:

    A session file from **tpm2_startauthsession**(1)'s **-S** option.

  * **-o**, **\--out-policy-file**=_POLICY\_FILE_:

    File to save the policy digest.

[common options](common/options.md)

[common tcti options](common/tcti.md)

# EXAMPLES

Start a *policy* session and extend it with a specific command like unseal.
Attempts to perform other operations would fail.

## Create an unseal-only policy
```
TPM_CC_UNSEAL=0x15E

tpm2_startauthsession -S session.dat

tpm2_policycommandcode -S session.dat -o policy.dat $TPM_CC_UNSEAL

tpm2_flushcontext -S session.dat
```

## Create the object with unseal-only auth policy
```
tpm2_createprimary -a o -o prim.ctx

tpm2_create -C prim.ctx -u sealkey.pub -r sealkey.priv -L policy.dat \
  -i- <<< "SEALED-SECRET"
```

## Try unseal operation
```
tpm2_load -C prim.ctx -u sealkey.pub -r sealkey.priv -n sealkey.name \
  -o sealkey.ctx

tpm2_startauthsession \--policy-session -S session.dat

tpm2_policycommandcode -S session.dat -o policy.dat $TPM_CC_UNSEAL

tpm2_unseal -p session:session.dat -c sealkey.ctx

tpm2_flushcontext -S session.dat
```

## Try any other operation
```
echo "Encrypt Me" > plain.txt

tpm2_encryptdecrypt -i plain.txt -o enc.txt -c sealkey.ctx

if [ $? != 0 ]; then
    echo "Expected that operations other than unsealing will fail"
fi
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
