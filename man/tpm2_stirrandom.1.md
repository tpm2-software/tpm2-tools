% tpm2_stirrandom(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_stirrandom**(1) - Add "additional information" into TPM RNG state.

# SYNOPSIS

**tpm2_stirrandom** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_stirrandom**(1) - Inject "additional information" as bytes into TPM entropy Protected Capability pool.

"Additional information" can be extracted from file specified as argument or
being read from *STDIN* if argument is not specified.

Up to 128 bytes can be injected at once through standard input to **tpm2_stirrandom**(1).

If input file is larger than 128 bytes, **tpm2_stirrandom**(1) will fail.

Adding data through **tpm2_stirrandom**(1) will trigger a reseeding of TPM
DRBG Protected Capability. It is used when performing any sensitive action
on a shielded location such as loading a persistent key or acting on a
Protected Capability like updating TPM firmware.

# OPTIONS

This command has no option

## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.)

# EXAMPLES

## Inject from stdin using echo
```bash
echo -n "myrandomdata" | tpm2_stirrandom
```

## Inject 64 bytes from stdin using a file
```bash
dd if=/dev/urandom bs=1 count=64 > myrandom.bin

tpm2_stirrandom < ./myrandom.bin
```

## Inject bytes from a file and reading up to 128 bytes
```bash
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

[returns](common/returns.md)

[footer](common/footer.md)
