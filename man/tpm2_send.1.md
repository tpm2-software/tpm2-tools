% tpm2_send(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_send**(1) - Send a raw command buffer to the TPM.

# SYNOPSIS

**tpm2_send** [*OPTIONS*]

# DESCRIPTION

**tpm2_send**(1) - Sends a TPM command to the TPM. The command is
read from a file as a binary stream and transmitted to the TPM using the TCTI
specified by the caller. The response received from the TPM is written to
the output file.

Likely the caller will want to redirect this to a file or into a
program to decode and display the response in a human readable form.

# OPTIONS

  * **-o**, **\--out-file**=_OUTPUT\_FILE_:

    Output file to send response buffer to. Defaults to stdout.

[common options](common/options.md)

[common tcti options](common/tcti.md)

# EXAMPLES

## Send and receive raw commands to TPM

Send the contents of *tpm2-command.bin* to a device and collect the response as *tpm2-response.bin*.

```
tpm2_send < tpm2-command.bin > tpm2-response.bin

tpm2_send < tpm2-command.bin -o tpm2-response.bin
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
