% tpm2_getcap(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_getcap**(1) - Display TPM capabilities in a human readable form.

# SYNOPSIS

**tpm2_getcap** [*OPTIONS*]

# DESCRIPTION

**tpm2_getcap**(1) - Query the TPM for it's capabilities / properties and print them to the console.

# OPTIONS

  * **-c**, **\--capability**=_CAPABILITY\_NAME_:

    The name of the capability group to query.
    Currently supported capability groups are:

    * **properties-fixed**:
      Display fixed TPM properties.

    * **properties-variable**:
      Display variable TPM properties.

    * **algorithms**:
      Display data about supported algorithms.

    * **commands**:
      Display data about supported commands.

    * **ecc-curves**:
      Display data about elliptic curves.

    * **pcrs**:
      Display currently allocated PCRs.

    * **handles-transient**:
      Display handles about transient objects.

    * **handles-persistent**:
      Display handles about persistent objects.

    * **handles-permanent**:
      Display handles about permanent objects.

    * **handles-pcr**:
      Display handles about PCRs.

    * **handles-nv-index**:
      Display handles about NV Indices.

    * **handles-loaded-session**:
      Display handles about both loaded HMAC and policy sessions.

    * **handles-saved-session**:
      Display handles about saved sessions.

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
```
tpm2_getcap \--capability properties-fixed
```

## To list the supported capability arguments to **-c**
```
tpm2_getcap -l
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
