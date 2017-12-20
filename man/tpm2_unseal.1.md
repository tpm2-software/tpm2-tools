% tpm2_unseal(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_unseal**(1) - Returns the data in a loaded Sealed Data Object.

# SYNOPSIS

**tpm2_unseal** [*OPTIONS*]

# DESCRIPTION

**tpm2_unseal**(1) - -returns the data in a loaded Sealed Data Object.

**NOTE**: The **--set-list** and **--pcr-input-file** options should only be
used for simple PCR authentication policies. For more complex policies the
tools should be ran in an execution environment that keeps the session context
alive and pass that session using the **--input-session-handle** option.

# OPTIONS

  * **-H**, **--item**=_ITEM\_HANDLE_:

    Item handle of loaded object.

  * **-c**, **--item-context**=_ITEM\_CONTEXT\_FILE_:

    Filename of the item context.

  * **-P**, **--pwdk**=_KEY\_PASSWORD_:

    Specifies the password of _ITEM\_HANDLE_. Passwords should follow the
    password formatting standards, see section "Password Formatting".

  * **-o**, **--out-file**=_OUT\_FILE_:

    Output file name, containing the unsealed data. Defaults to stdout if not specified.

  * **-S**, **--input-session-handle**=_SESSION\_HANDLE_:

    Optional Input session handle from a policy session for authorization.

  * **-L**, **--set-list**==_PCR\_SELECTION\_LIST_:

    The list of pcr banks and selected PCRs' ids.
    _PCR\_SELECTION\_LIST_ values should follow the
    pcr bank specifiers standards, see section "PCR Bank Specfiers".

  * **-F**,**--pcr-input-file=_PCR\_INPUT\_FILE_

    Optional Path or Name of the file containing expected pcr values for the specified index.
    Default is to read the current PCRs per the set list.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[password formatting](common/password.md)

[pcr bank specifiers](common/password.md)

# EXAMPLES

```
tpm2_unseal -H 0x81010001 -P abc123 -o out.dat
tpm2_unseal -c item.context -P abc123 -o out.dat
tpm2_unseal -H 0x81010001 -P "hex:123abc" -o out.dat
tpm2_unseal -c item.context -L sha1:0,1,2 -F out.dat
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
