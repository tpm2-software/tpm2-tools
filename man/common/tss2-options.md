# COMMON OPTIONS

This collection of options are common to all tss2 programs and provide
information that many users may expect.

  * **-h**, **\--help [man|no-man]**:
    Display the tools manpage. By default, it attempts to invoke the manpager for the tool,
    however, on failure will output a short tool summary. This is the same behavior if the
    "man" option argument is specified, however if explicit "man" is requested, the tool will
    provide errors from man on stderr. If the "no-man" option if specified, or the manpager fails,
    the short options will be output to stdout.

    To successfully use the manpages feature requires the manpages to be installed or on
    _MANPATH_, See **man**(1) for more details.

  * **-v**, **\--version**:
    Display version information for this tool, supported tctis and exit.
