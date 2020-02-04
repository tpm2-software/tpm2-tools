% tpm2_policynv(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_policynv**(1) - Evaluates policy authorization by comparing a specified
value against the contents in the specified NV Index.

# SYNOPSIS

**tpm2_policynv** [*OPTIONS*] [*ARGUMENT*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_policynv**(1) - This command evaluates policy authorization by comparing
the contents written to an NV index against the one specified in the tool
options. The tool takes two arguments - (1) The NV index specified as raw handle
or an offset value to the nv handle range "TPM2_HR_NV_INDEX" and (2) Comparison
operator for magnitude comparison and or bit test operations. In the
specification the NV index holding the data is called operandA and the data that
the user specifies to compare is called operandB. The comparison operator can be
specified as follows:
* "eq"  if operandA           =   operandB
* "neq" if operandA           !=  operandB
* "sgt" if signed operandA    >   signed operandB
* "ugt" if unsigned operandA  >   unsigned operandB
* "slt" if signed operandA    <   signed operandB
* "ult" if unsigned operandA  <   unsigned operandB
* "sge" if signed operandA    >=  signed operandB
* "uge" if unsigned operandA  >=  unsigned operandB
* "sle" if signed operandA    <=  unsigned operandB
* "ule" if unsigned operandA  <=  unsigned operandB
* "bs"  if all bits set in operandA are set in operandB
* "bc"  if all bits set in operandA are clear in operandB

# OPTIONS

  * **-C**, **\--hierarchy**=_OBJECT_:

    Specifies the hierarchy used to authorize.
    Supported options are:
      * **o** for **TPM_RH_OWNER**
      * **p** for **TPM_RH_PLATFORM**
      * **`<num>`** where a hierarchy handle or nv-index may be used.

    When **-C** isn't explicitly passed the index handle will be used to
    authorize against the index. The index auth value is set via the
    **-p** option to **tpm2_nvdefine**(1).

  * **-P**, **\--auth**=_AUTH_:

    Specifies the authorization value for the hierarchy.

  * **-L**, **\--policy**=_FILE_:

    File to save the policy digest.

  * **-S**, **\--session**=_FILE_:

    The policy session file generated via the **-S** option to
    **tpm2_startauthsession** or saved off of a previous tool run.

  * **\--offset**=_NATURAL_NUMBER_:

    The offset within the NV index to start comparing at. The size of the data
    starting at offset and ending at size of NV index shall not exceed the size
    of the operand specified in the options.

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash.

  * **-i**, **\--input**=_FILE_:

    Specifies the input file with data to compare to NV Index contents. In the
    standard specification, this is termed as operand or operandB more
    specifically . It can be specified as a file input or stdin if option
    value is a "-".

## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

Test if NV index content value is equal to an input number. To do this we first
create an NV index of size 1 byte and write a value. Eg. 0xAA. Next we attempt
to create a policy that becomes valid if the equality comparison operation of
the NV index content against the one specified in the tool options.

## Define the test NV Index and write the value 0xAA to it
```bash
nv_test_index=0x01500001
tpm2_nvdefine -C o -p nvpass $nv_test_index -a "authread|authwrite" -s 1
echo "aa" | xxd -r -p | tpm2_nvwrite -P nvpass -i- $nv_test_index
```

## Attempt defining policynv with wrong comparison value specified in options.
```bash
tpm2_startauthsession -S session.ctx --policy-session
### This should fail
echo 0xBB | tpm2_policynv -S session.ctx -L policy.nv -i- 0x1500001 eq -P nvpass
tpm2_flushcontext session.ctx
```

## Attempt defining policynv with right comparison value specified in options.
```bash
tpm2_startauthsession -S session.ctx --policy-session
### This should pass
echo 0xAA | tpm2_policynv -S session.ctx -L policy.nv -i- 0x1500001 eq -P nvpass
tpm2_flushcontext session.ctx
```

[returns](common/returns.md)

[limitations](common/policy-limitations.md)

[footer](common/footer.md)
