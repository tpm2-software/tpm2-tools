% tpm2_nvlist(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_nvlist**(1) - display all defined Non-Volatile (NV)s indices.

SYNOPSIS
--------

**tpm2_nvlist** [*OPTIONS*]

DESCRIPTION
-----------

**tpm2_nvlist**(1) - display all defined Non-Volatile (NV)s indices to stdout in a YAML format.

Display metadata for all defined NV indices. Metadata includes:

  * The size of the defined region.
  * The hash algorithm used to compute the name of the index.
  * The auth policy.
  * The NV attributes as defined in section "NV Attributes".

Example Output:
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

This tool takes no tool specific options.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[nv attributes](common/nv-attrs.md)

# EXAMPLES

To list the defined NV indeces to stdout:

```
tpm2_nvlist
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
