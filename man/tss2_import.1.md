% tss2_import(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_import**(1) -

# SYNOPSIS

**tss2_import** [*OPTIONS*]

[common fapi references](common/tss2-fapi-references.md)

# DESCRIPTION

**tss2_import**(1) - This command imports a JSON encoded key, policy or policy
template and stores it under the provided path.

# OPTIONS

These are the available options:

  * **-p**, **\--path**=_STRING_:

    The path of the new object.

  * **-i**, **\--importData**=_FILENAME_ or _-_ (for stdin):

    The data to be imported.

[common tss2 options](common/tss2-options.md)

# EXAMPLE
```
tss2_import --path=/policy/duplicate-policy --importData=importData.json
```
```
tss2_import --path=/ext/key --importData=importData.file
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
