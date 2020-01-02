% tpm2_eventlog(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_eventlog**(1) - Display tpm2 event log.

# SYNOPSIS

**tpm2_eventlog**  [*ARGUMENT*]

# DESCRIPTION

**tpm2_eventlog**(1) - Parse a binary TPM2 event log. The event log may be
passed to the tool as the final positional parameter. If this parameter is
omitted the tool will return an error. The format of this log documented in
the "TCG PC Client Platform Firmware Profile Specification".

# OPTIONS

This tool takes no tool specific options.

  * **ARGUMENT** The command line argument is the path to a binary TPM2
    eventlog.

## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

# EXAMPLES

```bash
# display eventlog from provided file
tpm2_eventlog eventlog.bin
```

[returns](common/returns.md)

[footer](common/footer.md)
