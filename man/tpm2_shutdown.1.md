% tpm2_shutdown(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_shutdown**(1) - Send a shutdown command to the TPM.

# SYNOPSIS

**tpm2_shutdown** [*OPTIONS*]

# DESCRIPTION

**tpm2_shutdown**(1) - Send a **TPM2_Shutdown** command with either
**TPM_SU_CLEAR** or **TPM_SU_STATE**.

# OPTIONS

  * **-c**, **\--clear**:

    Shutdown type sent will be **TPM_SU_CLEAR** instead of **TPM2_SU_STATE**.

## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

## Send a TPM Shutdown Command with flags TPM2\_SU\_STATE
```bash
tpm2_shutdown
```

## Send a TPM Shutdown Command with flags TPM2\_SU\_CLEAR
```bash
tpm2_shutdown -c
```

# NOTES

Typically a Resource Manager (like
[tpm2-abrmd](https://github.com/tpm2-software/tpm2-abrmd)) or low-level/boot
software will have already sent this command.

[returns](common/returns.md)

[footer](common/footer.md)
