% tpm2_getcap(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_getcap**(1) - Display TPM capabilities in a human readable form.

# SYNOPSIS

**tpm2_getcap** [*OPTIONS*] [*CAPABILITY*]

# DESCRIPTION

**tpm2_getcap**(1) - Query the TPM for it's capabilities / properties and print
them to the console. It takes a string form of the capability to query as an
argument to the tool. Currently supported capability groups are:

- **algorithms**:
  Display data about supported algorithms.

- **commands**:
  Display data about supported commands.

- **pcrs**:
  Display currently allocated PCRs.

- **properties-fixed**:
  Display fixed TPM properties.

- **properties-variable**:
  Display variable TPM properties.

- **ecc-curves**:
  Display data about elliptic curves.

- **handles-transient**:
  Display handles about transient objects.

- **handles-persistent**:
  Display handles about persistent objects.

- **handles-permanent**:
  Display handles about permanent objects.

- **handles-pcr**:
  Display handles about PCRs.

- **handles-nv-index**:
  Display handles about NV Indices.

- **handles-loaded-session**:
  Display handles about both loaded HMAC and policy sessions.

- **handles-saved-session**:
  Display handles about saved sessions.

# OPTIONS

  * **-l**, **\--list**:

    List known supported capability names. These names can be
    supplied as the argument to the **-c** option. Output is in a
    YAML compliant list to stdout.

    For example:
    ```
      - algorithms
      - commands
      - properties-fixed
      ...
    ```

[common options](common/options.md)

[common tcti options](common/tcti.md)

# EXAMPLES

## To list the fixed properties of the TPM
```bash
tpm2_getcap properties-fixed
```

## To list the supported capability groups
```bash
tpm2_getcap -l
```

[returns](common/returns.md)

[footer](common/footer.md)
