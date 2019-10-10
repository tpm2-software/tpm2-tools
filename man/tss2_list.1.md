% tss2_list(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_list**(1) -

# SYNOPSIS

**tss2_list** [*OPTIONS*]

# DESCRIPTION

**tss2_list**(1) - This command enumerates all objects in the metadata store in a given a path. The returned list SHALL consist of complete paths from the root (not relative paths from the search path), such that they can be directly used in another query. The values in this list SHALL be colon-separated.

# OPTIONS

These are the available options:

  * **-p**, **\--searchPath**:

    The path identifying the root of the search. MUST NOT be NULL.

  * **-o**, **\--pathList**:

    Returns the colon-separated list of paths. MUST NOT be NULL.

[common tss2 options](common/tss2-options.md)

# EXAMPLES

## List all entities
```
tss2_list
```
## List all entities under the HS path
```
tss2_list --searchPath HS --pathList output.file
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
