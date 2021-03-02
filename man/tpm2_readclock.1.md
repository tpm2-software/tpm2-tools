% tpm2_readclock(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_readclock**(1) - Retrieves the time information from the TPM.

# SYNOPSIS

**tpm2_readclock** [*OPTIONS*]

# DESCRIPTION

**tpm2_readclock**(1) -Reads the current TPMS\_TIME\_INFO structure from the
TPM. The structure contains the current setting of Time, Clock, resetCount, and
restartCount. The structure is output as YAML to stdout. The YAML output is
defined as:

```yaml
time: 13673142     # 64 bit value of time TPM has been powered on in ms.
clock_info:
  clock: 13673142  # 64 bit value of time TPM has been powered on since last TPM2_Clear in ms.
  reset_count: 0   # 32 bit value of the number of TPM Resets since the last
                   # TPM2_Clear.
  restart_count: 0 # 32 bit value of the number of times that TPM2_Shutdown or
                   # _TPM_Hash_Start have occurred since the last TPM Reset or
                   # TPM2_Clear.
  safe: yes        # boolean yes|no value that no value of Clock greater than
                   # the current value of Clock has been previously reported by
                   # the TPM.
```

This tool takes no arguments and no tool specific options.

## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

## Read the clock
```bash
tpm2_readclock
time: 13673142
clock_info:
  clock: 13673142
  reset_count: 0
  restart_count: 0
  safe: yes
```

[returns](common/returns.md)

[footer](common/footer.md)
