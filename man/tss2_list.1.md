% tss2_list(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_list**(1) -

# SYNOPSIS

**tss2_list** [*OPTIONS*]

# DESCRIPTION

**tss2_list**(1) - This command enumerates all objects in the metadata store in a given a path.

# OPTIONS

These are the available options:

  * **-p**, **\--searchPath** _STRING_:

    The path identifying the root of the search. Optional parameter. If omitted,
    all entities will be searched.

  * **-o**, **\--pathList** _FILENAME_ or _-_ (for stdout):

    Returns the colon-separated list of paths. Optional parameter. If omitted,
    results will be printed to _STDOUT_.

[common tss2 options](common/tss2-options.md)

# EXAMPLES

## List all entities and print results to stdout
```
tss2_list
```
## List all entities under the HS path and print results to file
```
tss2_list --searchPath HS --pathList output.file
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
