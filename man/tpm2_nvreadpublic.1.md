% tpm2_nvreadpublic(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_nvreadpublic**(1) - Display all defined Non-Volatile (NV)s indices.

# SYNOPSIS

**tpm2_nvreadpublic** [*OPTIONS*]

# DESCRIPTION

**tpm2_nvreadpublic**(1) - Display all defined Non-Volatile (NV)s indices to
stdout in a YAML format.

Display metadata for all defined NV indices. Metadata includes:

  * The size of the defined region.
  * The hash algorithm used to compute the name of the index.
  * The auth policy.
  * The NV attributes as defined in section "NV Attributes".

## Example Output
  ```
  0x1500015:
    hash algorithm:
      friendly: sha256
      value: 0xB
    attributes:
      friendly: ownerwrite|ownerread
      value: 0x2000200
    size: 32
    authorization policy:

  0x1500017:
    hash algorithm:
      friendly: sha256
      value: 0xB
    attributes:
      friendly: ownerwrite|ownerread
      value: 0x2000200
    size: 32
    authorization policy:
  ```

# OPTIONS

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash unless rphash is
    also required.

  * **\--rphash**=_FILE_

    File path to record the hash of the response parameters. This is commonly
    termed as rpHash.

  * **-S**, **\--session**=_POLICY_SESSION_:

    Specify an auxiliary session for auditing and or encryption/decryption of
    the parameters.

  * **-n**, **\--name**=_FILE_:

    The name of the NV index that must be provided when only calculating the
    cpHash without actually dispatching the command to the TPM.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[nv attributes](common/nv-attrs.md)

# EXAMPLES

## List the defined NV indices to stdout

```bash
tpm2_nvreadpublic
```

[returns](common/returns.md)

[footer](common/footer.md)
