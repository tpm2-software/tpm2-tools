tpm2_send_command 1 "SEPTEMBER 2017" tpm2-tools
==================================================

NAME
----

tpm2_send_command(1) - Send a raw command buffer to the TPM.

SYNOPSIS
--------

`tpm2_send_command` [OPTIONS]

DESCRIPTION
-----------

tpm2_send_command(1) Sends a TPM command to the TPM. The command is
read from a file as a binary stream and transmitted to the TPM using the TCTI
specified by the caller. The response received from the TPM is written to
the output file.

Likely the caller will want to redirect this to a file or into a
program to decode and display the response in a human readable form.

OPTIONS
-------

  * `-i`, `--input`=_INPUT\FILE_:

    Input file to read a command buffer from. Defaults to stdin.

  * `-o`, `--outFile`=_OUTPUT\_FILE_:

    Output file to send response buffer to. Defaults to stdout.

[common options](common/options.md)

[common tcti options](common/tcti.md)

EXAMPLES
--------

Send the contents of tpm2-command.bin to a device and collect the response as tpm2-response.bin.
All examples of below accomplish this task.
```
tpm2_send_command --tcti=device < tpm2-command.bin > tpm2-response.bin
tpm2_send_command --tcti=device -i tpm2-command.bin > tpm2-response.bin
tpm2_send_command --tcti=device < tpm2-command.bin -o tpm2-response.bin
tpm2_send_command --tcti=device -i tpm2-command.bin -o tpm2-response.bin
```

RETURNS
-------
0 on success or 1 on failure.

BUGS
----
[Github Issues](https://github.com/01org/tpm2-tools/issues)

HELP
----
See the [Mailing List](https://lists.01.org/mailman/listinfo/tpm2)