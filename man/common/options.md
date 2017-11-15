# COMMON OPTIONS

This collection of options are common to many programs and provide
information that many users may expect.

  * **-h**, **--help**:
    Display the tools manpage. This requires the manpages to be installed or on
    _MANPATH_, See man(1) for more details.

  * **-v**, **--version**:
	Display version information for this tool, supported tctis and exit.

  * **-V**, **--verbose**:
	Increase the information that the tool prints to the console during its
	execution. When using this option the file and line number are printed.

  * **-Q**, **--quiet**:
    Silence normal tool output to stdout.

  * **-Z**, **--enable-errata**:
    Enable the application of errata fixups. Useful if an errata fixup needs to be
    applied to commands sent to the TPM.