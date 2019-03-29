% tpm2_rc_decode(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_rc_decode**(1) - Decode TPM2 error codes to human readable format.

# SYNOPSIS

**tpm2_rc_decode** [*OPTIONS*] _RC\_CODE_

# DESCRIPTION

**tpm2_rc_decode**(1) - Converts _RC\_CODE_ originating from the SAPI and TCTI into
human readable errors. Analogous to **strerror**(3), but for the TPM2 stack.

# OPTIONS

This tool takes no tool specific options.

[common options](common/options.md)

# EXAMPLES

```
tpm2_rc_decode 0x100
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
