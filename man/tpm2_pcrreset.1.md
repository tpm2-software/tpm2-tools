% tpm2_pcrreset(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_pcrreset**(1) - Reset one or more PCR banks

# SYNOPSIS

**tpm2_pcrreset** [*OPTIONS*] _PCR\_INDEX_ ...

# DESCRIPTION

**tpm2_pcrreset**(1) - Reset PCR value in all banks for specified index.
More than one PCR index can be specified.

The reset value is manufacturer-dependent and is either sequence of 00 or FF
on the length of the hash algorithm for each supported bank.

_PCR\_INDEX_ is a space separated list of PCR indexes to be reset when issuing
the command.

# OPTIONS

This tool accepts no tool specific options.

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash.

[common options](common/options.md)

[common tcti options](common/tcti.md)

# EXAMPLES

## Reset a single PCR
```bash
tpm2_pcrreset 23
```

## Reset multiple PCRs
```bash
tpm2_pcrreset 16 23
```

# NOTES

On operating system's locality (generally locality 0), only PCR 23 can be reset.
PCR-16 can also be reset on this locality, depending on TPM manufacturers
which could define this PCR as resettable.

PCR 0 to 15 are not resettable (being part of SRTM). PCR 16 to 22 are mostly
reserved for DRTM or dedicated to specific localities and might not
be resettable depending on current TPM locality.

[returns](common/returns.md)

[footer](common/footer.md)
