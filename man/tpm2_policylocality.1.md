% tpm2_policylocality(1) tpm2-tools | General Commands Manual
%
% MARCH 2019

# NAME

**tpm2_policylocality**(1) - Restrict TPM object authorization to specific
TPM commands or operations.

# SYNOPSIS

**tpm2_policylocality** [*OPTIONS*] _LOCALITY_

# DESCRIPTION

**tpm2_policylocality**(1) - Restricts TPM object authorization to specific
TPM locality. Useful when you want to allow only specific locality
with the TPM object. As an argument it takes the _LOCALITY_ as an integer
value. Requires support for extended sessions with resource manager.

# OPTIONS

  * **-S**, **--session**=_SESSION\_FILE_:

    A session file from **tpm2_startauthsession**(1)'s **-S** option.

  * **-o**, **--out-policy-file**=_POLICY\_FILE_:

    File to save the policy digest.

[common options](common/options.md)

[common tcti options](common/tcti.md)

# EXAMPLES

Start a *policy* session and extend it with a specific locality number (like 3).
Attempts to perform other operations would fail.

## Create an policy restricted by locality 3
```
TPM_LOCALITY=0x3

tpm2_startauthsession -S session.dat

tpm2_policylocality -S session.dat -o policy.dat $TPM_LOCALITY

tpm2_flushcontext -S session.dat
```

## Create the object with auth policy
```
tpm2_createprimary -a o -o prim.ctx

tpm2_create -C prim.ctx -u sealkey.pub -r sealkey.priv -L policy.dat \
  -I- <<< "SEALED-SECRET"
```

## Try unseal operation
```
tpm2_load -C prim.ctx -u sealkey.pub -r sealkey.priv -n sealkey.name \
  -o sealkey.ctx

tpm2_startauthsession -a -S session.dat

tpm2_policylocality -S session.dat -o policy.dat $TPM_LOCALITY

# Change to locality 3, Note: this operation varies on different platforms

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

# NOTES

Locality control implementation is platform specific.

# LIMITATIONS

Currently there is no interface (from TSS to TPM linux driver) to set
locality for a discrete nor firmware TPM.

As for TPM simulator, there is no [tpm2-abrmd](https://github.com/tpm2-software/tpm2-abrmd) interface to change locality.
For now, one can set locality with TPM simulator, without [tpm2-abrmd](https://github.com/tpm2-software/tpm2-abrmd).

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
