% tpm2_unseal(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_unseal**(1) - Returns the data in a loaded Sealed Data Object.

# SYNOPSIS

**tpm2_unseal** [*OPTIONS*]

# DESCRIPTION

**tpm2_unseal**(1) - Returns the data in a loaded Sealed Data Object.

# OPTIONS

  * **-c**, **--context-object**=_CONTEXT\_OBJECT_:

    Context object for the loaded object. Either a file or a handle number.
    See section "Context Object Format".

  * **-p**, **--auth-key**=_KEY\_AUTH_:

    Optional authorization value to use the key specified by **-c**.
    Authorization values should follow the "authorization formatting standards",
    see section "Authorization Formatting".

  * **-o**, **--out-file**=_OUT\_FILE_:

    Output file name, containing the unsealed data. Defaults to stdout if not specified.

## Session Options

  Options used for internally controlling sessions and policy events. These
  are exclusive of **-P**.

  * **-L**, **--set-list**==_PCR\_SELECTION\_LIST_:

    The list of PCR banks and selected PCRs' ids.
    _PCR\_SELECTION\_LIST_ values should follow the
    PCR bank specifiers standards, see section "PCR Bank Specifiers".
    **-S** is mutually exclusive of this option.

  * **-F**,**--pcr-input-file**=_PCR\_INPUT\_FILE_

    Optional Path or Name of the file containing expected PCR values for the specified index.
    Default is to read the current PCRs per the set list.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[context object format](common/ctxobj.md)

[authorization formatting](common/authorizations.md)

[pcr bank specifiers](common/pcr.md)

# EXAMPLES

```
tpm2_unseal -c 0x81010001 -p abc123 -o out.dat

tpm2_unseal -c item.context -p abc123 -o out.dat

tpm2_unseal -c 0x81010001 -p "hex:123abc" -o out.dat

tpm2_unseal -c item.context -L sha1:0,1,2 -F out.dat
```

# NOTES

The **--set-list** and **--pcr-input-file** options should only be
used for simple PCR authentication policies. For more complex policies the
tools should be run in an execution environment that keeps the session context
alive and pass that session using the **--input-session-handle** option.

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
