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

- **vendor[:num]**:
  Displays the vendor properties as a hex buffer output. The string "vendor"
  can be suffixed with a colon followed by a number as understood by strtoul(3)
  with a 0 base. That value is used as the property value within the\
  TPM2\_GetCapability command, and defaults to 1. An example to call it with a
  property value of 2 is:
    tpm2\_getcap vendor:2

  NOTE: if vendor requests hang, try the "-i" option to ignore the moreData field and
  only read once.

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

  * **\--ignore-moredata**

  Ignores the moreData field when dealing with buggy TPM responses.

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
