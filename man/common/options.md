# COMMON OPTIONS

This collection of options are common to many programs and provide
information that many users may expect.

  * **-h**, **\--help=[man|no-man]**:
    Display the tools manpage. By default, it attempts to invoke the manpager for the tool,
    however, on failure will output a short tool summary. This is the same behavior if the
    "man" option argument is specified, however if explicit "man" is requested, the tool will
    provide errors from man on stderr. If the "no-man" option if specified, or the manpager fails,
    the short options will be output to stdout.

    To successfully use the manpages feature requires the manpages to be installed or on
    _MANPATH_, See man(1) for more details.

  * **-v**, **\--version**:
    Display version information for this tool, supported tctis and exit.

  * **-V**, **\--verbose**:
    Increase the information that the tool prints to the console during its
    execution. When using this option the file and line number are printed.

  * **-Q**, **\--quiet**:
    Silence normal tool output to stdout.

  * **-Z**, **\--enable-errata**:
    Enable the application of errata fixups. Useful if an errata fixup needs to be
    applied to commands sent to the TPM. Defining the environment
    TPM2TOOLS\_ENABLE\_ERRATA is equivalent.
  * **-R**, **\--autoflush**:
    Enable autoflush for transient objects created by the command. If a parent
    object is loaded from a context file also the transient parent object will
    be flushed. Autoflush can also be activated if the environment variable
    TPM2TOOLS\_AUTOFLUSH is is set to yes or true.
