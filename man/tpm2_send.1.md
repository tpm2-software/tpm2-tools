% tpm2_send(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_send**(1) - Send a raw command buffer to the TPM.

# SYNOPSIS

**tpm2_send** [*OPTIONS*] [*STDIN*]

# DESCRIPTION

**tpm2_send**(1) - Sends a TPM command to the TPM. The command is read from a
file as a binary stream and transmitted to the TPM using the TCTI specified by
the caller. The response received from the TPM is written to the output file.

Likely the caller will want to redirect this to a file or into a
program to decode and display the response in a human readable form.

# OPTIONS

  * **-o**, **\--output**=_FILE_:

    Output file to send response buffer to. Defaults to _STDOUT_.

  * **_STDIN** the file containing the TPM2 command.

## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

## Send and receive raw commands to TPM

Send the contents of *tpm2-command.bin* to a device and collect the response as *tpm2-response.bin*.

```bash
tpm2_send < tpm2-command.bin > tpm2-response.bin

tpm2_send < tpm2-command.bin -o tpm2-response.bin
```

[returns](common/returns.md)

[footer](common/footer.md)
