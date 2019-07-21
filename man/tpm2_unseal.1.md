% tpm2_unseal(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_unseal**(1) - Returns the data in a loaded Sealed Data Object.

# SYNOPSIS

**tpm2_unseal** [*OPTIONS*]

# DESCRIPTION

**tpm2_unseal**(1) - Returns the data in a loaded Sealed Data Object.

# OPTIONS

  * **-c**, **\--object-context**=_CONTEXT\_OBJECT_:

    Context object for the loaded object. Either a file or a handle number.
    See section "Context Object Format".

  * **-p**, **\--auth**=_KEY\_AUTH_:

    Optional authorization value to use the key specified by **-c**.
    Authorization values should follow the "authorization formatting standards",
    see section "Authorization Formatting".

  * **-o**, **\--output**=_OUT\_FILE_:

    Output file name, containing the unsealed data. Defaults to stdout if not specified.

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

tpm2_unseal -c item.context -p pcr:sha256:0,1+pcr.value -o out.dat
```

# NOTES

The **\--set-list** and **\--pcr-input-file** options should only be
used for simple PCR authentication policies. For more complex policies the
tools should be run in an execution environment that keeps the session context
alive and pass that session using the **\--input-session-handle** option.

[returns](common/returns.md)

[footer](common/footer.md)
