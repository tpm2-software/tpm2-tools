% tpm2_stirrandom(1) tpm2-tools | General Commands Manual
%
% MARCH 2019

# NAME

**tpm2_stirrandom**(1) - Add "additional information" into TPM RNG state.

# SYNOPSIS

**tpm2_stirrandom** [*OPTIONS*] _INPUT\_FILE_

# DESCRIPTION

**tpm2_stirrandom**(1) - Inject "additional information" as bytes into TPM entropy Protected Capability pool.

"Additional information" can be extracted from _INPUT\_FILE_ or being read from stdin
if _INPUT\_FILE_ is not specified.

Up to 128 bytes can be injected at once through standard input to **tpm2_stirrandom**(1).

If _INPUT\_FILE_ is larger than 128 bytes, **tpm2_stirrandom**(1) will fail.

Adding data through **tpm2_stirrandom**(1) will trigger a reseeding of TPM
DRBG Protected Capability. It is used when performing any sensitive action
on a shielded location such as loading a persistent key or acting on a
Protected Capability like updating TPM firmware.

# OPTIONS

This command has no option

[common options](common/options.md)

[common tcti options](common/tcti.md)

# EXAMPLES

## Inject from stdin using echo
```
echo -n "myrandomdata" | tpm2_stirrandom
```

## Inject 64 bytes from stdin using a file
```
dd if=/dev/urandom bs=1 count=64 > myrandom.bin

tpm2_stirrandom < ./myrandom.bin
```

## Inject bytes from a file and reading up to 128 bytes
```
dd if=/dev/urandom of=./myrandom.bin bs=1 count=42

tpm2_stirrandom ./myrandom.bin
```

# NOTES

Please be aware that even if the "additional information" added
by **tpm2_stirrandom**(1) can be entropy gathered from other DRBG
sources, the TPM has no way of determining if the value has any entropy or not.
As a consequence, it will just be considered as "additional input".

The "additional input" is as defined in [NIST SP800-90A](
https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-90.pdf)

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
